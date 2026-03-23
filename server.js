require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'cave_forum_secret_key_2026';

app.use(express.json());
app.use(cors());

mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('Connection failed:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role:     { type: String, enum: ['user', 'admin'], default: 'user' },
    bio:      { type: String, default: '' },
    joinDate: { type: Date, default: Date.now },
    isBanned: { type: Boolean, default: false },
    lastUsernameChange: { type: Date, default: 0 }
});
const User = mongoose.model('User', userSchema);

const replySchema = new mongoose.Schema({
    authorId:   String,
    authorName: String,
    body:       String,
    date:       { type: Date, default: Date.now },
    likes:      [String],
    replies: [{
        authorId:   String,
        authorName: String,
        body:       String,
        date:       { type: Date, default: Date.now }
    }]
});

const forumSchema = new mongoose.Schema({
    title:      { type: String, required: true },
    category:   { type: String, enum: ['General', 'Bug Reports', 'Feature Requests', 'Help & Support', 'Announcements'], default: 'General' },
    type:       { type: String, enum: ['Discussion', 'Bug', 'Question', 'Feedback'], default: 'Discussion' },
    body:       { type: String, required: true },
    authorId:   { type: String, required: true },
    authorName: String,
    status:     { type: String, enum: ['open', 'solved'], default: 'open' },
    views:      { type: Number, default: 0 },
    likes:      [String],
    date:       { type: Date, default: Date.now },
    lastActive: { type: Date, default: Date.now },
    solvedAt:   { type: Date, default: null },
    replies:    [replySchema],
    reports:    [{ reporterId: String, reason: String, date: { type: Date, default: Date.now } }]
});
const Forum = mongoose.model('Forum', forumSchema);

function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    try {
        req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
}

async function runCleanup() {
    const twentyDaysAgo = new Date(Date.now() - 20 * 86400000);
    const threeDaysAgo  = new Date(Date.now() - 3  * 86400000);
    try {
        const r = await Forum.deleteMany({
            $or: [
                { lastActive: { $lt: twentyDaysAgo }, status: 'open' },
                { status: 'solved', solvedAt: { $lt: threeDaysAgo } }
            ]
        });
        if (r.deletedCount) console.log(`[Cleanup] Deleted ${r.deletedCount} forum(s).`);
    } catch (e) { console.error('[Cleanup] Failed:', e); }
}
runCleanup();
setInterval(runCleanup, 86400000);

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ error: 'All fields required.' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        const exists = await User.findOne({ $or: [{ username }, { email }] });
        if (exists) return res.status(409).json({ error: 'Username or email already taken.' });
        const passwordHash = await bcrypt.hash(password, 12);
        const user = new User({ username, email, passwordHash });
        await user.save();
        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
        res.status(201).json({ token, user: { id: user._id, username: user.username, email: user.email, role: user.role, bio: user.bio } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { login, password } = req.body;
        const user = await User.findOne({ $or: [{ username: login }, { email: login }] });
        if (!user) return res.status(401).json({ error: 'Invalid username or password.' });
        if (user.isBanned) return res.status(403).json({ error: 'Your account has been banned.' });
        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) return res.status(401).json({ error: 'Invalid username or password.' });
        const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, user: { id: user._id, username: user.username, email: user.email, role: user.role, bio: user.bio, joinDate: user.joinDate } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-passwordHash');
        if (!user) return res.status(404).json({ error: 'User not found.' });
        res.json(user);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/auth/settings', authMiddleware, async (req, res) => {
    try {
        const { bio, username, currentPassword, newPassword } = req.body;
        const user = await User.findById(req.user.id);
        if (bio !== undefined) user.bio = bio;
        if (username && username !== user.username) {
            const oneWeekAgo = new Date(Date.now() - 7 * 86400000);
            if (user.lastUsernameChange > oneWeekAgo) return res.status(403).json({ error: 'Username can only be changed once per week.' });
            const taken = await User.findOne({ username });
            if (taken) return res.status(409).json({ error: 'Username already taken.' });
            user.username = username;
            user.lastUsernameChange = new Date();
        }
        if (newPassword) {
            if (!currentPassword) return res.status(400).json({ error: 'Current password required.' });
            const valid = await bcrypt.compare(currentPassword, user.passwordHash);
            if (!valid) return res.status(401).json({ error: 'Current password is incorrect.' });
            user.passwordHash = await bcrypt.hash(newPassword, 12);
        }
        await user.save();
        res.json({ id: user._id, username: user.username, email: user.email, bio: user.bio, role: user.role });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/forum', async (req, res) => {
    try {
        const filter = {};
        if (req.query.category) filter.category = req.query.category;
        const posts = await Forum.find(filter).sort({ lastActive: -1 }).select('-reports');
        res.json(posts);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/forum/:id', async (req, res) => {
    try {
        const post = await Forum.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true });
        if (!post) return res.status(404).json({ error: 'Not found.' });
        res.json(post);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/forum', authMiddleware, async (req, res) => {
    try {
        const { title, category, type, body } = req.body;
        if (!title || !body) return res.status(400).json({ error: 'Title and body required.' });
        const post = new Forum({ title, category, type, body, authorId: req.user.id, authorName: req.user.username });
        await post.save();
        res.status(201).json(post);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/forum/:id', authMiddleware, async (req, res) => {
    try {
        const post = await Forum.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Not found.' });
        if (post.authorId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized.' });
        const { title, body, category, type } = req.body;
        if (title) post.title = title;
        if (body) post.body = body;
        if (category) post.category = category;
        if (type) post.type = type;
        await post.save();
        res.json(post);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/forum/:id', authMiddleware, async (req, res) => {
    try {
        const post = await Forum.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Not found.' });
        if (post.authorId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized.' });
        await post.deleteOne();
        res.json({ message: 'Deleted.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/forum/:id/like', authMiddleware, async (req, res) => {
    try {
        const post = await Forum.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Not found.' });
        const idx = post.likes.indexOf(req.user.id);
        if (idx === -1) post.likes.push(req.user.id);
        else post.likes.splice(idx, 1);
        await post.save();
        res.json({ likes: post.likes.length, liked: idx === -1 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/forum/:id/solve', authMiddleware, async (req, res) => {
    try {
        const post = await Forum.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Not found.' });
        if (post.authorId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized.' });
        post.status = 'solved';
        post.solvedAt = new Date();
        await post.save();
        res.json({ message: 'Marked as solved. Will be deleted in 3 days.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/forum/:id/reply', authMiddleware, async (req, res) => {
    try {
        const { body } = req.body;
        if (!body) return res.status(400).json({ error: 'Reply body required.' });
        const post = await Forum.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Not found.' });
        post.replies.push({ authorId: req.user.id, authorName: req.user.username, body });
        post.lastActive = new Date();
        await post.save();
        res.status(201).json(post);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/forum/:id/reply/:replyId/subreply', authMiddleware, async (req, res) => {
    try {
        const { body } = req.body;
        const post = await Forum.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Not found.' });
        const reply = post.replies.id(req.params.replyId);
        if (!reply) return res.status(404).json({ error: 'Reply not found.' });
        reply.replies.push({ authorId: req.user.id, authorName: req.user.username, body });
        post.lastActive = new Date();
        await post.save();
        res.status(201).json(post);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/forum/:id/reply/:replyId/like', authMiddleware, async (req, res) => {
    try {
        const post = await Forum.findById(req.params.id);
        const reply = post.replies.id(req.params.replyId);
        if (!reply) return res.status(404).json({ error: 'Reply not found.' });
        const idx = reply.likes.indexOf(req.user.id);
        if (idx === -1) reply.likes.push(req.user.id);
        else reply.likes.splice(idx, 1);
        await post.save();
        res.json({ likes: reply.likes.length, liked: idx === -1 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/forum/:id/report', authMiddleware, async (req, res) => {
    try {
        const { reason } = req.body;
        const post = await Forum.findById(req.params.id);
        if (!post) return res.status(404).json({ error: 'Not found.' });
        post.reports.push({ reporterId: req.user.id, reason });
        await post.save();
        res.json({ message: 'Report submitted.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/reports', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const posts = await Forum.find({ 'reports.0': { $exists: true } }).select('title authorName reports date');
        res.json(posts);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().select('-passwordHash').sort({ joinDate: -1 });
        res.json(users);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/user/:id/ban', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found.' });
        user.isBanned = !user.isBanned;
        await user.save();
        res.json({ message: user.isBanned ? 'User banned.' : 'User unbanned.', isBanned: user.isBanned });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/forum/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        await Forum.findByIdAndDelete(req.params.id);
        res.json({ message: 'Forum deleted by admin.' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));