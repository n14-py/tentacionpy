// =============================================
// IMPORTACIONES Y CONFIGURACIÓN INICIAL
// =============================================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const ejs = require('ejs');
const crypto = require('crypto');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', ejs.renderFile);

// =============================================
// CONEXIÓN A MONGODB
// =============================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/tentacionpy_final_db')
  .then(() => console.log('✅ Conectado a MongoDB'))
  .catch(err => console.error('❌ Error de conexión a MongoDB:', err));

// =============================================
// CONFIGURACIÓN DE CLOUDINARY
// =============================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const getPublicId = (url) => {
    try {
        if (!url || !url.includes('cloudinary')) return null;
        const parts = url.split('/');
        const versionIndex = parts.findIndex(part => part.startsWith('v'));
        if (versionIndex === -1) return null;
        const publicIdWithFormat = parts.slice(versionIndex + 1).join('/');
        return publicIdWithFormat.substring(0, publicIdWithFormat.lastIndexOf('.'));
    } catch (e) { console.error("Error extrayendo public_id:", e); return null; }
};

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: (req, file) => ({
        folder: 'tentacionpy_final',
        resource_type: 'auto',
        allowed_formats: ['jpeg', 'png', 'jpg', 'mp4', 'mov', 'avi'],
        transformation: file.mimetype.startsWith('image/') ? [{
            overlay: { font_family: "Poppins", font_size: 50, font_weight: "bold", text: "tentacionpy.com" },
            color: "#FFFFFF", opacity: 40, gravity: "south_east", x: 20, y: 20
        }] : [{
            overlay: { font_family: "Poppins", font_size: 80, text: "tentacionpy.com" },
            color: "white", opacity: 50, gravity: "center"
        }]
    })
});
const upload = multer({ storage });


// =============================================
// CONSTANTES Y MODELOS DE DATOS (ACTUALIZADOS)
// =============================================
const CITIES = ['Asunción', 'Central', 'Ciudad del Este', 'Encarnación', 'Villarrica', 'Coronel Oviedo', 'Pedro Juan Caballero', 'Otra'];
const CATEGORIES = ['Acompañante', 'Masajes', 'OnlyFans', 'Contenido Digital', 'Shows', 'Otro'];
const CREATOR_EARNING_RATE = 0.55;
const PAGOPAR_PUBLIC_TOKEN = "db3515375d0ac2ba2745b6355458c687";
const PAGOPAR_PRIVATE_TOKEN = "280e500fb8bc93cd782d7fa4435de2f8";

// Schemas
const donationSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, amount: Number }, { timestamps: true });
const commentSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, text: String, donation: donationSchema }, { timestamps: true });
const subscriptionSchema = new mongoose.Schema({ subscriberId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, endDate: Date }, { timestamps: true });

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String }, googleId: { type: String },
    gender: { type: String, enum: ['Mujer', 'Hombre', 'Trans'] }, orientation: { type: String, enum: ['Heterosexual', 'Homosexual', 'Bisexual'] },
    location: { type: String, enum: CITIES }, bio: String, whatsapp: String, profilePic: { type: String, default: '/img/default.png' },
    tpysBalance: { type: Number, default: 100 }, isVerified: { type: Boolean, default: true },
    purchasedVideos: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    likedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }], isAdmin: { type: Boolean, default: false },
    subscriptions: [{ creatorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, endDate: Date }],
    subscribers: [subscriptionSchema],
    subscriptionSettings: { isActive: { type: Boolean, default: false }, price: { type: Number, enum: [300, 600, 1000, 1250], default: 300 } },
    achievements: { tenSubscribers: { claimed: Boolean }, thousandFollowers: { claimed: Boolean }, tenVideoSales: { claimed: Boolean } },
    automatedChatMessage: { type: String, default: "¡Hola! Gracias por suscribirte. Pide tu video personalizado, ¡precios al privado!" },
    automatedMessageEnabled: { type: Boolean, default: true }
}, { timestamps: true });

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, type: { type: String, enum: ['image', 'video'] }, files: [String],
    description: String, whatsapp: String, category: { type: String, enum: CATEGORIES }, tags: [String], address: String, services: [String], rate: String,
    price: { type: Number, default: 0 }, salesCount: { type: Number, default: 0 }, isSubscriberOnly: { type: Boolean, default: false },
    views: { type: Number, default: 0 }, likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], comments: [commentSchema],
    boostedUntil: Date,
    boostOptions: { color: String, label: String }
}, { timestamps: true });

const transactionSchema = new mongoose.Schema({
    type: { type: String, enum: ['video_purchase', 'subscription', 'donation', 'achievement_reward', 'boost', 'tpys_purchase', 'chat_tip'] },
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' }, amount: Number, netEarning: Number,
    currency: { type: String, enum: ['TPYS', 'PYG'], default: 'TPYS' },
    paymentGatewayId: String,
    status: { type: String, enum: ['PENDIENTE', 'COMPLETADO', 'CANCELADO'], default: 'COMPLETADO' }
}, { timestamps: true });

const withdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, amount: Number, method: String,
    details: { fullName: String, ci: String, bankName: String, accountNumber: String, phone: String, alias: String },
    status: { type: String, enum: ['Pendiente', 'Procesado', 'Rechazado'], default: 'Pendiente' }
}, { timestamps: true });

const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['like', 'comment', 'follow', 'subscribe', 'sale', 'donation', 'message', 'tip'] },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' }, isRead: { type: Boolean, default: false },
    message: String,
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
    conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation' },
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    tpysAmount: { type: Number, default: 0 },
    isRead: { type: Boolean, default: false }
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);


// =============================================
// MIDDLEWARES Y PASSPORT
// =============================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET || 'super-secret-key-12345', resave: false, saveUninitialized: true, cookie: { secure: 'auto' } }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

const formatDate = (date) => {
    if (!date) return '';
    const d = new Date(date);
    const now = new Date();
    const diffSeconds = Math.round((now - d) / 1000);
    if (diffSeconds < 60) return 'Justo ahora';
    const diffMinutes = Math.round(diffSeconds / 60);
    if (diffMinutes < 60) return `Hace ${diffMinutes} min`;
    const diffHours = Math.round(diffMinutes / 60);
    if (diffHours < 24) return `Hace ${diffHours} h`;
    return d.toLocaleDateString('es-PY');
};

app.use(async (req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.CITIES = CITIES;
    res.locals.CATEGORIES = CATEGORIES;
    res.locals.formatDate = formatDate;
    res.locals.unreadNotifications = 0;
    res.locals.path = req.path;
    if (req.user) {
        res.locals.unreadNotifications = await Notification.countDocuments({ userId: req.user._id, isRead: false });
    }
    next();
});

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user || !user.password) return done(null, false, { message: 'Credenciales incorrectas.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Credenciales incorrectas.' });
        return done(null, user);
    } catch (err) { return done(err); }
}));

const CALLBACK_URL = `${process.env.BASE_URL || 'http://localhost:3000'}/auth/google/callback`;
passport.use(new GoogleStrategy({ clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: CALLBACK_URL },
  async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
            if (!user.googleId) { user.googleId = profile.id; }
            await user.save();
            return done(null, user);
        }
        const newUser = new User({
            googleId: profile.id,
            username: profile.displayName.replace(/\s/g, '').toLowerCase() + Math.floor(Math.random() * 1000),
            email: profile.emails[0].value,
            profilePic: profile.photos[0].value,
            isVerified: true,
            gender: 'Mujer',
            orientation: 'Heterosexual'
        });
        await newUser.save();
        return done(null, newUser);
    } catch (err) { return done(err, null); }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } catch (err) { done(err); }
});

const requireAuth = (req, res, next) => req.isAuthenticated() ? next() : res.redirect('/login');
const requireAdmin = (req, res, next) => (req.isAuthenticated() && req.user.isAdmin) ? next() : res.status(403).render('error', { message: "Acceso denegado." });
const isPostOwner = async (req, res, next) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).render('error', { message: "Publicación no encontrada." });
        if (!post.userId.equals(req.user._id) && !req.user.isAdmin) return res.status(403).render('error', { message: "No eres el dueño." });
        res.locals.post = post;
        next();
    } catch (err) { next(err); }
};

// =============================================
// RUTAS PRINCIPALES Y DE PERFIL
// =============================================
app.get('/', (req, res) => res.redirect('/feed'));

app.get('/feed', async (req, res, next) => {
    try {
        let filter = {};
        const { location, gender, category, q } = req.query;
        if (category) filter.category = category;
        const userFilter = {};
        if (location) userFilter.location = location;
        if (gender) userFilter.gender = gender;
        if (Object.keys(userFilter).length > 0) {
            const userIds = (await User.find(userFilter).select('_id')).map(u => u._id);
            filter.userId = { $in: userIds };
        }
        if (q) {
            const regex = { $regex: q, $options: 'i' };
            const userIdsByName = (await User.find({ username: regex }).select('_id')).map(u => u._id);
            const orConditions = [{ description: regex }, { tags: regex }, { userId: { $in: userIdsByName } }];
            filter.$or = filter.$or ? [...filter.$or, ...orConditions] : orConditions;
        }
        const posts = await Post.find(filter).populate('userId').sort({ boostedUntil: -1, createdAt: -1 });
        res.render('index', { posts, query: req.query });
    } catch (err) { next(err); }
});

app.get('/register', (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res, next) => {
    try {
        const { username, email, password, gender, orientation, location, ageCheck } = req.body;
        if (!ageCheck) throw new Error("Debes confirmar que eres mayor de edad.");
        if (!password) throw new Error("La contraseña es requerida.");
        const existingUser = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
        if (existingUser) throw new Error('El email o nombre de usuario ya está en uso.');
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({ username, email, password: hashedPassword, gender, orientation, location });
        await user.save();
        req.login(user, (err) => { if (err) return next(err); res.redirect('/feed'); });
    } catch (err) { res.render('register', { error: err.message }); }
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', passport.authenticate('local', { successRedirect: '/feed', failureRedirect: '/login' }));

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        req.session.destroy(() => res.redirect('/'));
    });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/feed'));

app.get('/profile', requireAuth, (req, res) => res.redirect(`/user/${req.user.username}`));

app.get('/user/:username', async (req, res, next) => {
    try {
        const userProfile = await User.findOne({ username: req.params.username.toLowerCase() });
        if (!userProfile) return res.status(404).render('error', { message: 'Usuario no encontrado' });
        const posts = await Post.find({ userId: userProfile._id }).sort({ createdAt: -1 });
        let isSubscribed = false;
        if (req.user) {
            isSubscribed = !!req.user.subscriptions.find(s => s.creatorId.equals(userProfile._id) && new Date(s.endDate) > new Date());
        }
        const viewToRender = req.user && req.user._id.equals(userProfile._id) ? 'profile' : 'user-profile';
        res.render(viewToRender, { userProfile, posts, isSubscribed });
    } catch (err) { next(err); }
});

// =============================================
// RUTA PARA "MIS VIDEOS" (Y OTRAS PÁGINAS DE CONTENIDO)
// =============================================

app.get('/my-videos', requireAuth, async (req, res, next) => {
    try {
        // Buscamos al usuario y poblamos la información de los videos comprados
        // y también la información del creador de cada video.
        const user = await User.findById(req.user._id).populate({
            path: 'purchasedVideos',
            model: 'Post',
            populate: {
                path: 'userId',
                model: 'User',
                select: 'username profilePic' // Solo traemos los datos necesarios
            }
        });

        if (!user) {
            // Esta comprobación es por seguridad, aunque es poco probable que falle.
            return res.status(404).render('error', { message: 'Usuario no encontrado.' });
        }
        
        // Pasamos la lista de videos a la vista 'my-videos.html'
        res.render('my-videos', { videos: user.purchasedVideos });
    } catch (err) {
        // Si hay un error en la base de datos, lo pasamos al manejador de errores.
        next(err);
    }
});

app.post('/user/:id/follow', requireAuth, async (req, res, next) => {
    try {
        const userToFollow = await User.findById(req.params.id);
        if (!userToFollow || req.user._id.equals(userToFollow._id)) return res.redirect('back');
        
        const currentUser = await User.findById(req.user._id);
        const isFollowing = currentUser.following.some(id => id.equals(userToFollow._id));

        if (isFollowing) {
            await User.findByIdAndUpdate(currentUser._id, { $pull: { following: userToFollow._id } });
            await User.findByIdAndUpdate(userToFollow._id, { $pull: { followers: currentUser._id } });
        } else {
            await User.findByIdAndUpdate(currentUser._id, { $addToSet: { following: userToFollow._id } });
            await User.findByIdAndUpdate(userToFollow._id, { $addToSet: { followers: currentUser._id } });
            await new Notification({ userId: userToFollow._id, actorId: currentUser._id, type: 'follow' }).save();
        }
        res.redirect('back');
    } catch (err) { next(err); }
});


// =============================================
// RUTAS DE POSTS Y CONTENIDO
// =============================================
app.get('/new-post', requireAuth, (req, res) => res.render('new-post'));

app.post('/new-post', requireAuth, upload.array('files', 10), async (req, res, next) => {
    try {
        const { type, description, price, services, rate, address, whatsapp, category, tags, isSubscriberOnly } = req.body;
        if (!req.files || req.files.length === 0) throw new Error("Debes subir al menos un archivo.");
        const newPost = new Post({
            userId: req.user._id, type, files: req.files.map(f => f.path), description, whatsapp: whatsapp || req.user.whatsapp, category,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            price: type === 'video' && !(isSubscriberOnly === 'on') ? parseFloat(price) : 0,
            services: type === 'image' && services ? services.split(',').map(s => s.trim()) : [],
            rate: type === 'image' ? rate : '',
            address: type === 'image' ? address : '',
            isSubscriberOnly: isSubscriberOnly === 'on'
        });
        await newPost.save();
        res.redirect(`/anuncio/${newPost._id}`);
    } catch (err) { next(err); }
});

app.get('/anuncio/:id', async (req, res, next) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true })
            .populate('userId').populate({ path: 'comments', populate: { path: 'userId', select: 'username profilePic' } });
        if (!post) return res.status(404).render('error', { message: 'Anuncio no encontrado.' });
        let canView = true, isOwner = false, hasPurchased = false, hasSubscriptionAccess = false;
        if (req.user) {
            isOwner = post.userId.equals(req.user._id);
            if (post.type === 'video') {
                hasPurchased = req.user.purchasedVideos.includes(post._id);
                const sub = req.user.subscriptions.find(s => s.creatorId.equals(post.userId._id) && new Date(s.endDate) > new Date());
                hasSubscriptionAccess = post.isSubscriberOnly && !!sub;
                canView = isOwner || hasPurchased || hasSubscriptionAccess || req.user.isAdmin;
            }
        }
        res.render('anuncio-detail', { post, canView, isOwner, hasPurchased, hasSubscriptionAccess });
    } catch (err) { next(err); }
});

app.post('/post/:id/delete', requireAuth, isPostOwner, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    dbSession.startTransaction();
    try {
        const post = res.locals.post;
        for (const fileUrl of post.files) {
            const publicId = getPublicId(fileUrl);
            if (publicId) {
                await cloudinary.uploader.destroy(publicId, { resource_type: fileUrl.includes('/video/') ? 'video' : 'image' }).catch(err => console.log("Cloudinary destroy failed (non-critical):", err));
            }
        }
        await Post.findByIdAndDelete(req.params.id, { session: dbSession });
        await dbSession.commitTransaction();
        res.json({ success: true, redirectUrl: '/profile' });
    } catch (err) {
        await dbSession.abortTransaction();
        next(err);
    } finally {
        dbSession.endSession();
    }
});

app.post('/post/:id/like', requireAuth, async (req, res, next) => {
    try {
        const post = await Post.findById(req.params.id);
        const isLiked = req.user.likedPosts.includes(post._id);
        const update = isLiked ? { $pull: { likes: req.user._id } } : { $addToSet: { likes: req.user._id } };
        const userUpdate = isLiked ? { $pull: { likedPosts: post._id } } : { $addToSet: { likedPosts: post._id } };
        await Post.findByIdAndUpdate(post._id, update);
        await User.findByIdAndUpdate(req.user._id, userUpdate);
        if (!isLiked && !post.userId.equals(req.user._id)) {
            await new Notification({ userId: post.userId, actorId: req.user._id, type: 'like', postId: post._id }).save();
        }
        const updatedPost = await Post.findById(post._id);
        res.json({ success: true, likes: updatedPost.likes.length, liked: !isLiked });
    } catch (err) { res.status(500).json({ success: false }); }
});

app.post('/post/:id/comments', requireAuth, async (req, res, next) => {
    const { text, donationAmount } = req.body;
    const dbSession = await mongoose.startSession();
    dbSession.startTransaction();
    try {
        const post = await Post.findById(req.params.id).session(dbSession);
        if (!post) throw new Error("Post no encontrado");
        const commenter = await User.findById(req.user._id).session(dbSession);
        const amount = Number(donationAmount) || 0;
        if (amount > 0 && commenter.tpysBalance < amount) throw new Error("No tienes suficientes TPYS para donar.");
        
        const newCommentData = { userId: commenter._id, text };
        if (amount > 0) {
            const creator = await User.findById(post.userId).session(dbSession);
            const netEarning = amount * CREATOR_EARNING_RATE;
            commenter.tpysBalance -= amount;
            creator.tpysBalance += netEarning;
            newCommentData.donation = { userId: commenter._id, amount };
            await new Transaction({ type: 'donation', sellerId: creator._id, buyerId: commenter._id, postId: post._id, amount, netEarning }).save({ session: dbSession });
            await new Notification({ userId: creator._id, actorId: commenter._id, type: 'donation', postId: post._id, message: `te donó ${amount} TPYS en tu post.` }).save({ session: dbSession });
            await commenter.save({ session: dbSession });
            await creator.save({ session: dbSession });
        }
        
        post.comments.push(newCommentData);
        await post.save({ session: dbSession });
        
        if (!post.userId.equals(commenter._id)) {
            await new Notification({ userId: post.userId, actorId: commenter._id, type: 'comment', postId: post._id, message: `comentó tu post.` }).save({ session: dbSession });
        }
        
        await dbSession.commitTransaction();
        const newComment = post.comments[post.comments.length - 1];
        const populatedComment = await newComment.populate('userId', 'username profilePic');
        res.json({ success: true, comment: populatedComment });
    } catch (err) {
        await dbSession.abortTransaction();
        res.status(500).json({ success: false, message: err.message });
    } finally {
        dbSession.endSession();
    }
});


// =============================================
// --- RUTAS DE PÁGINAS QUE FALTABAN ---
// =============================================

app.get('/my-videos', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({
            path: 'purchasedVideos',
            populate: { path: 'userId', select: 'username profilePic' }
        });
        res.render('my-videos', { videos: user.purchasedVideos });
    } catch (err) {
        next(err);
    }
});

app.get('/my-likes', requireAuth, async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id).populate({
            path: 'likedPosts',
            populate: { path: 'userId', select: 'username profilePic' }
        });
        res.render('my-likes', { posts: user.likedPosts });
    } catch (err) {
        next(err);
    }
});

app.get('/notifications', requireAuth, async (req, res, next) => {
    try {
        const notifications = await Notification.find({ userId: req.user._id })
            .populate('actorId', 'username profilePic')
            .sort({ createdAt: -1 });
        
        // Marcar como leídas al verlas
        await Notification.updateMany({ userId: req.user._id, isRead: false }, { $set: { isRead: true }});
        
        res.render('notifications', { notifications });
    } catch (err) {
        next(err);
    }
});

app.get('/terms', (req, res) => {
    res.render('terms');
});

app.get('/payout-info', requireAuth, (req, res) => {
    res.render('payout-info');
});


// =============================================
// RUTAS DE MONETIZACIÓN (COMPRA, SUSCRIPCIÓN, PROMOCIÓN)
// =============================================
app.post('/post/:id/boost', requireAuth, isPostOwner, async (req, res, next) => {
    const { boost, boostLabel, boostColor } = req.body;
    const dbSession = await mongoose.startSession();
    dbSession.startTransaction();
    try {
        const post = res.locals.post;
        const user = await User.findById(req.user._id).session(dbSession);
        const [plan, cost] = boost.split('_');
        const boostCost = parseInt(cost, 10);
        let boostDays = { viral: 1, tendencia: 3, hot: 10 }[plan];
        
        if (user.tpysBalance < boostCost) throw new Error('No tienes suficientes TPYS para esta promoción.');
        
        user.tpysBalance -= boostCost;
        post.boostedUntil = new Date(Date.now() + boostDays * 24 * 60 * 60 * 1000);
        post.boostOptions = { color: boostColor, label: boostLabel };
        
        await new Transaction({ type: 'boost', buyerId: user._id, postId: post._id, amount: boostCost, netEarning: 0 }).save({ session: dbSession });
        await user.save({ session: dbSession });
        await post.save({ session: dbSession });
        
        await dbSession.commitTransaction();
        res.json({ success: true, message: "¡Anuncio promocionado con éxito!", redirectUrl: `/anuncio/${post._id}` });
    } catch (err) {
        await dbSession.abortTransaction();
        res.status(400).json({ success: false, message: err.message });
    } finally {
        dbSession.endSession();
    }
});

app.post('/buy-video/:id', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    dbSession.startTransaction();
    try {
        const post = await Post.findById(req.params.id).session(dbSession);
        if (!post || post.type !== 'video' || post.isSubscriberOnly) throw new Error('Video no disponible para compra.');
        const buyer = await User.findById(req.user._id).session(dbSession);
        if (buyer.tpysBalance < post.price) throw new Error('No tienes suficientes TPYS.');
        if (buyer.purchasedVideos.includes(post._id)) throw new Error('Ya has comprado este video.');
        
        const seller = await User.findById(post.userId).session(dbSession);
        const price = post.price;
        const netEarning = price * CREATOR_EARNING_RATE;
        buyer.tpysBalance -= price;
        seller.tpysBalance += netEarning;
        buyer.purchasedVideos.push(post._id);
        post.salesCount += 1;
        
        await buyer.save({ session: dbSession });
        await seller.save({ session: dbSession });
        await post.save({ session: dbSession });
        await new Transaction({ type: 'video_purchase', sellerId: seller._id, buyerId: buyer._id, postId: post._id, amount: price, netEarning }).save({ session: dbSession });
        await new Notification({ userId: seller._id, actorId: buyer._id, type: 'sale', postId: post._id, message: `vendió su video.` }).save({ session: dbSession });
        
        await dbSession.commitTransaction();
        res.json({ success: true, message: "¡Compra exitosa! El video ahora está en 'Mis Compras'." });
    } catch (err) {
        await dbSession.abortTransaction();
        res.status(400).json({ success: false, message: err.message });
    } finally {
        dbSession.endSession();
    }
});

app.post('/user/:id/subscribe', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    dbSession.startTransaction();
    try {
        const creator = await User.findById(req.params.id).session(dbSession);
        if (!creator || !creator.subscriptionSettings.isActive) throw new Error("Este creador no tiene las suscripciones activas.");
        const buyer = await User.findById(req.user._id).session(dbSession);
        const price = creator.subscriptionSettings.price;
        if (buyer._id.equals(creator._id)) throw new Error("No puedes suscribirte a ti mismo.");
        if (buyer.tpysBalance < price) throw new Error("No tienes suficientes TPYS.");
        
        const netEarning = price * CREATOR_EARNING_RATE;
        buyer.tpysBalance -= price;
        creator.tpysBalance += netEarning;
        
        const now = new Date();
        const existingSubIndex = buyer.subscriptions.findIndex(s => s.creatorId.equals(creator._id));
        let newEndDate = new Date(new Date(now).setMonth(now.getMonth() + 1));

        if (existingSubIndex > -1) {
            const currentEndDate = new Date(buyer.subscriptions[existingSubIndex].endDate);
            if (currentEndDate > now) {
                newEndDate = new Date(currentEndDate.setMonth(currentEndDate.getMonth() + 1));
            }
            buyer.subscriptions[existingSubIndex].endDate = newEndDate;
        } else {
            buyer.subscriptions.push({ creatorId: creator._id, endDate: newEndDate });
        }
        
        const subscriberIndex = creator.subscribers.findIndex(s => s.subscriberId.equals(buyer._id));
        if (subscriberIndex > -1) {
            creator.subscribers[subscriberIndex].endDate = newEndDate;
        } else {
            creator.subscribers.push({ subscriberId: buyer._id, endDate: newEndDate });
        }
        
        // Iniciar conversación si no existe
        let conversation = await Conversation.findOne({ participants: { $all: [buyer._id, creator._id] } });
        if (!conversation) {
             conversation = new Conversation({ participants: [buyer._id, creator._id] });
             await conversation.save({ session: dbSession });
             if(creator.automatedMessageEnabled && creator.automatedChatMessage) {
                const autoMessage = new Message({ conversationId: conversation._id, senderId: creator._id, text: creator.automatedChatMessage });
                conversation.lastMessage = autoMessage._id;
                await autoMessage.save({ session: dbSession });
                await conversation.save({ session: dbSession });
                await new Notification({ userId: buyer._id, actorId: creator._id, type: 'message', message: "Te ha enviado un mensaje automático." }).save({ session: dbSession });
             }
        }

        await new Transaction({ type: 'subscription', sellerId: creator._id, buyerId: buyer._id, amount: price, netEarning }).save({ session: dbSession });
        await new Notification({ userId: creator._id, actorId: buyer._id, type: 'subscribe', message: `se ha suscrito a tu perfil.` }).save({ session: dbSession });
        
        await buyer.save({ session: dbSession });
        await creator.save({ session: dbSession });
        
        await dbSession.commitTransaction();
        res.json({ success: true, message: '¡Suscripción exitosa!' });
    } catch (err) {
        await dbSession.abortTransaction();
        res.status(400).json({ success: false, message: err.message });
    } finally {
        dbSession.endSession();
    }
});

// =============================================
// RUTAS DE PAGOPAR
// =============================================
app.get('/add-funds', requireAuth, (req, res) => res.render('add-funds'));

app.post('/pagopar/create-order', requireAuth, async (req, res) => {
    try {
        const { amountGs, tpysAmount } = req.body;
        const amount = parseInt(amountGs, 10);
        const orderId = `TPY-${req.user._id.toString().slice(-4)}-${Date.now()}`;
        const hash = crypto.createHash('md5').update(PAGOPAR_PRIVATE_TOKEN + orderId + amount).digest('hex');
        
        const orderData = {
            "token": hash,
            "comprador": { "ruc": "0", "email": req.user.email, "nombre": req.user.username, "telefono": "0999999999", "direccion": "N/A", "documento": "0", "razon_social": req.user.username, "tipo_documento": "CI" },
            "public_key": PAGOPAR_PUBLIC_TOKEN,
            "monto_total": amount,
            "tipo_pedido": "VENTA-COMERCIO",
            "id_pedido_comercio": orderId,
            "descripcion_resumen": `Compra de ${tpysAmount} TPYS`,
            "fecha_maxima_pago": new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10).replace(/-/g, ""),
            "url_retorno_ok": `${process.env.BASE_URL || 'http://localhost:3000'}/payment-success`,
            "url_retorno_error": `${process.env.BASE_URL || 'http://localhost:3000'}/payment-error`,
            "url_notificacion_pedido": `${process.env.BASE_URL || 'http://localhost:3000'}/pagopar/callback`
        };

        const response = await fetch('https://api.pagopar.com/api/pedido/generar', {
            method: 'POST',
            body: JSON.stringify(orderData),
            headers: { 'Content-Type': 'application/json' }
        });
        const jsonResponse = await response.json();

        if (jsonResponse.respuesta === true) {
            await new Transaction({
                type: 'tpys_purchase', buyerId: req.user._id, amount, netEarning: parseInt(tpysAmount, 10),
                currency: 'PYG', paymentGatewayId: orderId, status: 'PENDIENTE'
            }).save();
            res.json({ success: true, paymentUrl: jsonResponse.resultado[0].data });
        } else {
            throw new Error(jsonResponse.resultado || 'Error con Pagopar');
        }
    } catch (err) {
        console.error("Error creating Pagopar order:", err);
        res.status(500).json({ success: false, message: 'Error al crear la orden de pago.' });
    }
});

app.post('/pagopar/callback', async (req, res) => {
    const { hash, id_pedido_comercio, estado, forma_pago } = req.body;
    const localHash = crypto.createHash('sha1').update(PAGOPAR_PRIVATE_TOKEN + id_pedido_comercio + estado).digest('hex');
    if (hash !== localHash) return res.status(403).send("Hash inválido.");

    if (estado === 'pagado') {
        const dbSession = await mongoose.startSession();
        dbSession.startTransaction();
        try {
            const transaction = await Transaction.findOne({ paymentGatewayId: id_pedido_comercio, status: 'PENDIENTE' }).session(dbSession);
            if (transaction) {
                const user = await User.findById(transaction.buyerId).session(dbSession);
                user.tpysBalance += transaction.netEarning;
                transaction.status = 'COMPLETADO';
                await user.save({ session: dbSession });
                await transaction.save({ session: dbSession });
            }
            await dbSession.commitTransaction();
            res.status(200).send("OK");
        } catch (err) {
            await dbSession.abortTransaction();
            res.status(500).send("Error interno al procesar el pago.");
        } finally {
            dbSession.endSession();
        }
    } else if (estado === 'cancelado') {
        await Transaction.findOneAndUpdate({ paymentGatewayId: id_pedido_comercio, status: 'PENDIENTE' }, { status: 'CANCELADO' });
        res.status(200).send("OK");
    } else {
        res.status(200).send("OK");
    }
});

app.get('/payment-success', (req, res) => res.render('payment-status', { success: true, message: '¡Pago exitoso! Tu saldo ha sido actualizado.' }));
app.get('/payment-error', (req, res) => res.render('payment-status', { success: false, message: 'El pago ha fallado o ha sido cancelado.' }));


// =============================================
// RUTAS DE CHAT
// =============================================
app.get('/chat', requireAuth, async (req, res, next) => {
    try {
        let conversations = await Conversation.find({ participants: req.user._id })
            .populate('participants', 'username profilePic')
            .populate({ path: 'lastMessage', select: 'text createdAt' })
            .sort({ 'lastMessage.createdAt': -1 });
        res.render('chat-list', { conversations });
    } catch (err) { next(err); }
});

app.get('/chat/with/:userId', requireAuth, async (req, res, next) => {
    const { userId } = req.params;
    try {
        let conversation = await Conversation.findOne({
            participants: { $all: [req.user._id, userId] }
        });
        if (!conversation) {
            const creator = await User.findById(userId);
            const isSubscribed = req.user.subscriptions.some(s => s.creatorId.equals(creator._id) && new Date(s.endDate) > new Date());
            if (!isSubscribed && !req.user._id.equals(creator._id)) {
                return res.status(403).render('error', { message: 'Debes suscribirte para iniciar un chat.' });
            }
            conversation = new Conversation({ participants: [req.user._id, userId] });
            await conversation.save();
        }
        res.redirect(`/chat/${conversation._id}`);
    } catch (err) { next(err); }
});

app.get('/chat/:conversationId', requireAuth, async (req, res, next) => {
    try {
        const conversation = await Conversation.findById(req.params.conversationId).populate('participants', 'username profilePic');
        if (!conversation || !conversation.participants.some(p => p._id.equals(req.user._id))) {
            return res.status(403).render('error', { message: 'No tienes acceso a este chat.' });
        }
        const messages = await Message.find({ conversationId: conversation._id }).populate('senderId', 'username profilePic').sort('createdAt');
        const otherUser = conversation.participants.find(p => !p._id.equals(req.user._id));
        res.render('chat-detail', { conversation, messages, otherUser });
    } catch (err) { next(err); }
});

app.post('/chat/:conversationId/messages', requireAuth, async (req, res, next) => {
    const { text, tpysAmount } = req.body;
    const amount = Number(tpysAmount) || 0;
    const dbSession = await mongoose.startSession();
    dbSession.startTransaction();
    try {
        const conversation = await Conversation.findById(req.params.conversationId).session(dbSession);
        if (!conversation.participants.includes(req.user._id)) throw new Error("No eres parte de esta conversación.");
        
        const sender = await User.findById(req.user._id).session(dbSession);
        const receiverId = conversation.participants.find(p => !p.equals(sender._id));
        const receiver = await User.findById(receiverId).session(dbSession);

        if (amount > 0) {
            if (sender.tpysBalance < amount) throw new Error("No tienes suficientes TPYS para enviar esta propina.");
            const netEarning = amount * CREATOR_EARNING_RATE;
            sender.tpysBalance -= amount;
            receiver.tpysBalance += netEarning;
            await new Transaction({ type: 'chat_tip', sellerId: receiver._id, buyerId: sender._id, amount, netEarning }).save({ session: dbSession });
            await new Notification({ userId: receiver._id, actorId: sender._id, type: 'tip', message: `te envió ${amount} TPYS en el chat.` }).save({ session: dbSession });
        }
        
        const newMessage = new Message({ conversationId: conversation._id, senderId: sender._id, text, tpysAmount: amount });
        conversation.lastMessage = newMessage._id;

        await sender.save({ session: dbSession });
        if(amount > 0) await receiver.save({ session: dbSession });
        await newMessage.save({ session: dbSession });
        await conversation.save({ session: dbSession });

        await dbSession.commitTransaction();
        const populatedMessage = await newMessage.populate('senderId', 'username profilePic');
        res.json({ success: true, message: populatedMessage });
    } catch (err) {
        await dbSession.abortTransaction();
        res.status(400).json({ success: false, message: err.message });
    } finally {
        dbSession.endSession();
    }
});


// =============================================
// RUTAS DEL PANEL DE CONFIGURACIÓN
// =============================================
app.get('/settings/:page', requireAuth, async (req, res, next) => {
    try {
        const { page } = req.params;
        const validPages = ['dashboard', 'profile', 'subscriptions', 'automations', 'payouts'];
        if (!validPages.includes(page)) return res.redirect('/settings/dashboard');

        let data = { page }; // Pasamos la página actual para el menú activo

        if (page === 'dashboard') {
            const transactions = await Transaction.find({ sellerId: req.user._id }).populate('buyerId', 'username').populate('postId', 'description').sort({ createdAt: -1 });
            const totalNetEarnings = transactions.reduce((sum, t) => sum + (t.netEarning || 0), 0);
            const activeSubscribers = req.user.subscribers.filter(s => new Date(s.endDate) > new Date()).length;
            data = { ...data, totalNetEarnings, transactions, activeSubscribersCount: activeSubscribers };
        }
        if (page === 'payouts') {
            data.withdrawals = await Withdrawal.find({ userId: req.user._id }).sort({ createdAt: -1 });
        }

        res.render(`settings/${page}`, data);
    } catch(err) { next(err); }
});

app.post('/settings/profile', requireAuth, upload.single('profilePic'), async (req, res, next) => {
    try {
        const { username, bio, location, whatsapp, gender, orientation } = req.body;
        const userToUpdate = await User.findById(req.user._id);
        if (req.file && userToUpdate.profilePic && !userToUpdate.profilePic.includes('default.png')) {
            const publicId = getPublicId(userToUpdate.profilePic);
            if (publicId) await cloudinary.uploader.destroy(publicId);
        }
        const updateData = { username, bio, location, whatsapp, gender, orientation };
        if (req.file) updateData.profilePic = req.file.path;
        await User.findByIdAndUpdate(req.user._id, updateData);
        res.redirect('/settings/profile');
    } catch (err) { next(err); }
});

app.post('/settings/subscriptions', requireAuth, async (req, res) => {
    const { isActive, price } = req.body;
    req.user.subscriptionSettings.isActive = isActive === 'on';
    if (price) req.user.subscriptionSettings.price = Number(price);
    await req.user.save();
    res.redirect('/settings/subscriptions');
});

app.post('/settings/automations', requireAuth, async (req, res) => {
    const { automatedMessageEnabled, automatedChatMessage } = req.body;
    req.user.automatedMessageEnabled = automatedMessageEnabled === 'on';
    req.user.automatedChatMessage = automatedChatMessage;
    await req.user.save();
    res.redirect('/settings/automations');
});

app.post('/settings/payouts', requireAuth, async (req, res, next) => {
    try {
        const { amount, method, fullName, ci, bankName, accountNumber, phone, alias } = req.body;
        const user = req.user;
        const amountNum = parseInt(amount);
        if (isNaN(amountNum) || amountNum < 30000) throw new Error(`El monto mínimo es de 30.000 Gs.`);
        const tpysToWithdraw = Math.floor(amountNum / 100);
        if (user.tpysBalance < tpysToWithdraw) throw new Error("No tienes suficientes TPYS para retirar ese monto.");
        
        let details = {};
        if (method === 'transferencia') details = { fullName, ci, bankName, accountNumber, alias };
        else if (method === 'giro') details = { fullName, ci, phone };
        else throw new Error("Método de retiro no válido.");
        
        await User.findByIdAndUpdate(user._id, { $inc: { tpysBalance: -tpysToWithdraw } });
        await new Withdrawal({ userId: user._id, amount: amountNum, method, details, status: 'Pendiente' }).save();
        
        res.redirect('/settings/payouts');
    } catch(err) { next(err); }
});


// =============================================
// RUTAS DE ADMINISTRADOR
// =============================================
app.get('/admin/dashboard', requireAdmin, async (req, res, next) => {
    try {
        const thirtyDaysAgo = new Date(new Date().setDate(new Date().getDate() - 30));
        
        const [totalUsers, totalPosts, tpysPurchases, platformEarnings, totalSubscriptions, totalWithdrawals] = await Promise.all([
            User.countDocuments(),
            Post.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
            Transaction.find({ type: 'tpys_purchase', status: 'COMPLETADO', createdAt: { $gte: thirtyDaysAgo } }),
            Transaction.find({ type: { $in: ['video_purchase', 'subscription', 'donation', 'chat_tip', 'boost'] }, createdAt: { $gte: thirtyDaysAgo } }),
            Transaction.countDocuments({ type: 'subscription', createdAt: { $gte: thirtyDaysAgo } }),
            Withdrawal.find({ status: 'Pendiente' }).countDocuments()
        ]);
        
        const totalGsSold = tpysPurchases.reduce((sum, t) => sum + t.amount, 0);
        const totalTpysSold = tpysPurchases.reduce((sum, t) => sum + t.netEarning, 0);
        const totalCommissionTpys = platformEarnings.reduce((sum, t) => {
            if(t.type === 'boost') return sum + t.amount;
            return sum + (t.amount - t.netEarning);
        }, 0);

        const stats = {
            totalUsers, totalPosts, totalGsSold, totalTpysSold, totalCommissionTpys, totalSubscriptions, pendingWithdrawals: totalWithdrawals
        };

        // Borrar datos antiguos si es necesario
        const twoMonthsAgo = new Date(new Date().setMonth(new Date().getMonth() - 2));
        await Transaction.deleteMany({ createdAt: { $lt: twoMonthsAgo } });
        await Notification.deleteMany({ createdAt: { $lt: twoMonthsAgo } });

        res.render('admin-dashboard', { stats });
    } catch (err) { next(err); }
});

app.get('/admin/withdrawals', requireAdmin, async (req, res, next) => {
    try {
        const withdrawals = await Withdrawal.find().populate('userId', 'username email').sort({ createdAt: -1 });
        res.render('admin-withdrawals', { withdrawals });
    } catch (err) { next(err); }
});
app.post('/admin/withdrawal/:id/update', requireAdmin, async (req, res, next) => {
    try {
        const { status } = req.body;
        const withdrawal = await Withdrawal.findById(req.params.id);
        if (withdrawal.status === 'Pendiente' && status === 'Rechazado') {
            const tpysToReturn = Math.floor(withdrawal.amount / 100);
            await User.findByIdAndUpdate(withdrawal.userId, { $inc: { tpysBalance: tpysToReturn } });
        }
        withdrawal.status = status;
        await withdrawal.save();
        res.redirect('/admin/withdrawals');
    } catch (err) { next(err); }
});

// =============================================
// MANEJADORES DE ERRORES Y ARRANQUE
// =============================================
app.use((req, res, next) => { res.status(404).render('error', { message: 'Página no encontrada (404)' }); });
app.use((err, req, res, next) => {
  console.error("❌ ERROR CAPTURADO:", err);
  res.status(err.status || 500).render('error', { message: err.message || 'Ocurrió un error inesperado.' });
});

app.listen(PORT, () => console.log(`🚀 Servidor TentacionPY corriendo en http://localhost:${PORT}`));