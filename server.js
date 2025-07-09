require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const multer = require('multer');
const ejs = require('ejs');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// =============================================
// CONFIGURACIÓN INICIAL
// =============================================
const app = express();
const PORT = process.env.PORT || 3000;

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', ejs.renderFile);

// =============================================
// CONEXIÓN A MONGODB
// =============================================
mongoose.connect(process.env.MONGODB_URI)
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

if (process.env.CLOUDINARY_CLOUD_NAME) {
    console.log('✅ Cloudinary configurado correctamente.');
} else {
    console.warn('⚠️  Advertencia: Faltan las variables de entorno de Cloudinary. Las subidas de archivos fallarán.');
}

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: (req, file) => {
        let params = {
            folder: 'tentacionpy',
            resource_type: 'auto',
            allowed_formats: ['jpeg', 'png', 'jpg', 'mp4', 'mov', 'avi']
        };

        if (file.mimetype.startsWith('image/')) {
            params.transformation = [{
                overlay: {
                    font_family: "Poppins",
                    font_size: 50,
                    font_weight: "bold",
                    text: "tentacionpy.com"
                },
                color: "#FFFFFF",
                opacity: 40,
                gravity: "south_east",
                x: 20,
                y: 20
            }];
        }
        return params;
    }
});

const upload = multer({ storage: storage });

// =============================================
// CONSTANTES Y MODELOS
// =============================================
const CITIES = ['Asunción', 'Central', 'Ciudad del Este', 'Encarnación', 'Villarrica', 'Coronel Oviedo', 'Pedro Juan Caballero', 'Otra'];
const CATEGORIES = ['Acompañante', 'Masajes', 'OnlyFans', 'Contenido Digital', 'Shows', 'Otro'];
const TPYS_TO_GS_RATE = 100;

const commentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
}, { timestamps: true });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: false },
  gender: { type: String, enum: ['Mujer', 'Hombre', 'Trans'], required: true },
  orientation: { type: String, enum: ['Heterosexual', 'Homosexual', 'Bisexual'], required: true },
  location: { type: String, enum: CITIES, default: 'Asunción' },
  bio: { type: String, default: '' },
  whatsapp: { type: String, default: '' },
  profilePic: { type: String, default: '/img/default.png' },
  tpysBalance: { type: Number, default: 100 },
  isVerified: { type: Boolean, default: true },
  purchasedVideos: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['image', 'video'], required: true },
  files: [{ type: String }],
  description: { type: String, required: true },
  whatsapp: { type: String, default: '' },
  category: { type: String, enum: CATEGORIES, default: 'Otro' },
  tags: { type: [String], default: [] },
  services: { type: [String], default: [] },
  rate: { type: String, default: '' },
  price: { type: Number, default: 0 },
  salesCount: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [commentSchema],
  boostedUntil: { type: Date },
  boostOptions: {
      color: { type: String, default: 'linear-gradient(140deg, #53122c, #240b19)' },
      emoji: { type: String, default: '🔥' }
  }
}, { timestamps: true });

const transactionSchema = new mongoose.Schema({
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    amount: { type: Number, required: true },
    platformFee: { type: Number, required: true },
    netEarning: { type: Number, required: true },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

// =============================================
// MIDDLEWARES
// =============================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: 'auto', maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));
const requireAuth = (req, res, next) => { if (!req.session.userId) return res.redirect('/login'); next(); };
const redirectIfAuth = (req, res, next) => { if (req.session.userId) return res.redirect('/profile'); next(); };
const isPostOwner = async (req, res, next) => {
    try {
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).render('error', { message: "Publicación no encontrada." });
        if (post.userId.toString() !== req.session.userId) return res.status(403).render('error', { message: "No tienes permiso para realizar esta acción." });
        res.locals.post = post;
        next();
    } catch (err) { res.status(500).render('error', { message: "Error al verificar el post." }); }
};
app.use(async (req, res, next) => {
  res.locals.currentUser = null;
  res.locals.CITIES = CITIES;
  res.locals.CATEGORIES = CATEGORIES;
  if (req.session.userId) {
    try { res.locals.currentUser = await User.findById(req.session.userId); }
    catch (err) { console.error('Error al cargar usuario:', err); }
  }
  next();
});
app.locals.formatDate = (date) => new Date(date).toLocaleString('es-ES', { day: '2-digit', month: 'short', year: 'numeric' });

// =============================================
// CONFIGURACIÓN DE PASSPORT
// =============================================
const CALLBACK_URL = `${process.env.BASE_URL || 'http://localhost:3000'}/auth/google/callback`;
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (user) {
            return done(null, user);
        } else {
            const newUser = new User({
                username: profile.displayName.replace(/\s/g, '') + Math.floor(Math.random() * 1000),
                email: profile.emails[0].value,
                password: await bcrypt.hash(Date.now().toString() + profile.id, 10),
                profilePic: profile.photos[0].value.replace(/=s96-c$/, '=s256-c'),
                isVerified: true,
                gender: 'Mujer',
                orientation: 'Heterosexual',
                location: 'Asunción',
            });
            await newUser.save();
            return done(null, newUser);
        }
    } catch (err) { return done(err, null); }
  }
));
passport.serializeUser((user, done) => { done(null, user.id); });
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) { done(err, null); }
});

// =============================================
// RUTAS
// =============================================
app.get('/', (req, res) => res.redirect('/feed'));
app.get('/feed', async (req, res, next) => {
    try {
        const { location, gender, q, category } = req.query;
        let postFilter = { type: 'image' };
        let userFilter = {};
        if (location && location !== "") userFilter.location = location;
        if (gender && gender !== "") userFilter.gender = gender;
        if (category && category !== "") postFilter.category = category;

        const userIdsByProperties = await User.find(userFilter).select('_id');
        let finalFilter = { ...postFilter, userId: { $in: userIdsByProperties.map(u => u._id) } };

        if (q) {
            const regex = { $regex: q, $options: 'i' };
            const userIdsByName = await User.find({ username: regex }).select('_id');
            const userIdsCombined = [...new Set([...userIdsByProperties.map(u => u._id.toString()), ...userIdsByName.map(u => u._id.toString())])];
            finalFilter = { 
                type: 'image', 
                $or: [ 
                    { userId: { $in: userIdsCombined } }, 
                    { description: regex }, 
                    { services: regex },
                    { tags: regex } 
                ] 
            };
        }
        const posts = await Post.find(finalFilter).populate('userId').sort({ boostedUntil: -1, createdAt: -1 });
        res.render('index', { posts, query: req.query });
    } catch (err) { next(err); }
});

app.get('/terms', (req, res) => res.render('terms'));
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login', failureMessage: true }), (req, res) => {
    req.session.userId = req.user.id;
    res.redirect('/profile');
});
app.get('/register', redirectIfAuth, (req, res) => res.render('register', { error: null }));
app.post('/register', async (req, res, next) => {
    try {
        const { username, email, password, gender, orientation, location, ageCheck } = req.body;
        if (!ageCheck) throw new Error("Debes confirmar que tienes más de 18 años.");
        const existingUser = await User.findOne({ $or: [{email}, {username}] });
        if(existingUser) throw new Error('El email o nombre de usuario ya está en uso.');
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword, gender, orientation, location });
        await user.save();
        req.session.userId = user._id;
        res.redirect('/profile');
    } catch (err) { next(err); }
});
app.get('/login', redirectIfAuth, (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).render('login', { error: 'Credenciales incorrectas' });
    req.session.userId = user._id;
    res.redirect('/profile');
  } catch (err) { next(err); }
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));
app.get('/settings', requireAuth, (req, res) => res.render('settings', { error: null, success: null }));
app.post('/settings/delete-account', requireAuth, async (req, res, next) => {
    try {
        const { password } = req.body;
        const user = await User.findById(req.session.userId);
        if(!user) return res.render('settings', { error: 'Usuario no encontrado.', success: null });
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.render('settings', { error: 'Contraseña incorrecta. No se ha podido borrar la cuenta.', success: null });
        await Post.deleteMany({ userId: user._id });
        await User.updateMany({ $or: [{ followers: user._id }, { following: user._id }] }, { $pull: { followers: user._id, following: user._id } });
        await User.findByIdAndDelete(user._id);
        req.session.destroy(() => res.redirect('/register'));
    } catch (err) { next(err); }
});
app.get('/profile', requireAuth, async (req, res, next) => {
 try{
    const user = await User.findById(req.session.userId);
    const posts = await Post.find({ userId: user._id }).sort({ createdAt: -1 });
    res.render('profile', { user, posts });
 } catch(err) { next(err); }
});
app.get('/user/:id', requireAuth, async (req, res, next) => {
    try{
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).render('error', { message: 'Usuario no encontrado' });
        const posts = await Post.find({ userId: user._id }).sort({ createdAt: -1 });
        res.render('user-profile', { user, posts });
    } catch(err) { next(err); }
});
app.get('/edit-profile', requireAuth, (req, res) => res.render('edit-profile'));
app.post('/edit-profile', requireAuth, upload.single('profilePic'), async (req, res, next) => {
    try {
        const { username, bio, location, whatsapp, gender, orientation } = req.body;
        const updateData = { username, bio, location, whatsapp, gender, orientation };
        if (req.file) { updateData.profilePic = req.file.path; }
        await User.findByIdAndUpdate(req.session.userId, updateData);
        res.redirect('/profile');
    } catch (err) { next(err); }
});
app.get('/user/:id/followers', requireAuth, async (req, res) => {
    const user = await User.findById(req.params.id).populate('followers', 'username profilePic');
    res.render('followers', { title: 'Seguidores', user, list: user.followers });
});
app.get('/user/:id/following', requireAuth, async (req, res) => {
    const user = await User.findById(req.params.id).populate('following', 'username profilePic');
    res.render('followers', { title: 'Siguiendo', user, list: user.following });
});
app.post('/user/:id/follow', requireAuth, async (req, res) => {
    try {
        const userToFollow = await User.findById(req.params.id);
        const currentUser = await User.findById(req.session.userId);
        if (currentUser.following.includes(userToFollow._id)) {
            currentUser.following.pull(userToFollow._id);
            userToFollow.followers.pull(currentUser._id);
        } else {
            currentUser.following.push(userToFollow._id);
            userToFollow.followers.push(currentUser._id);
        }
        await currentUser.save();
        await userToFollow.save();
        res.redirect('back');
    } catch (err) { res.status(500).render('error', { message: "Error al seguir al usuario" }); }
});
app.get('/new-post', requireAuth, (req, res) => res.render('new-post'));
app.post('/new-post', requireAuth, upload.array('files', 10), async (req, res, next) => {
    try {
        const { type, description, price, services, rate, whatsapp, category, tags } = req.body;
        if (!req.files || req.files.length === 0) throw new Error("No se ha seleccionado ningún archivo para subir.");
        
        const filePaths = req.files.map(file => file.path);

        const newPostData = {
            userId: req.session.userId,
            type,
            files: filePaths,
            description,
            whatsapp,
            category,
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            price: type === 'video' ? parseFloat(price) : 0,
            services: type === 'image' && services ? services.split(',').map(s => s.trim()) : [],
            rate: type === 'image' ? rate : ''
        };

        const newPost = new Post(newPostData);
        await newPost.save();
        res.redirect('/profile');
    } catch (err) { next(err); }
});

app.get('/post/:id/edit', requireAuth, isPostOwner, async (req, res) => res.render('edit-post', { post: res.locals.post }));
app.post('/post/:id/edit', requireAuth, isPostOwner, async (req, res, next) => {
    try {
        const { description, services, rate, whatsapp, price, category, tags } = req.body;
        const post = res.locals.post;
        post.description = description;
        post.category = category;
        post.tags = tags ? tags.split(',').map(t => t.trim()) : [];

        if (post.type === 'image') {
            post.services = services ? services.split(',').map(s => s.trim()) : [];
            post.rate = rate; 
            post.whatsapp = whatsapp;
        } else { 
            post.price = price; 
        }
        await post.save();
        res.redirect(post.type === 'image' ? `/anuncio/${post._id}` : '/profile');
    } catch (err) { next(err); }
});
app.post('/post/:id/delete', requireAuth, isPostOwner, async (req, res, next) => {
    try {
        await Post.findByIdAndDelete(req.params.id);
        res.redirect('/profile');
    } catch (err) { next(err); }
});
app.get('/anuncio/:id', async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true })
                                .populate('userId')
                                .populate('comments.userId', 'username profilePic');
        if (!post || post.type !== 'image') return res.status(404).render('error', { message: 'Anuncio no encontrado.' });
        res.render('anuncio-detail', { post });
    } catch (err) { res.status(500).render('error', { message: 'Error al cargar el anuncio.' }); }
});

app.get('/post/:id', requireAuth, async (req, res) => {
    try {
        const post = await Post.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } }, { new: true })
                                .populate('userId')
                                .populate('comments.userId', 'username profilePic');

        if (!post || post.type !== 'video') return res.status(404).render('error', { message: 'Publicación no válida.' });
        
        const user = res.locals.currentUser;
        const isOwner = post.userId.equals(user._id);
        const hasPurchased = user.purchasedVideos.includes(post._id);

        if (!isOwner && !hasPurchased) return res.status(403).render('error', { message: 'Debes comprar este video para verlo.' });
        
        res.render('post-detail', { post });
    } catch (err) { res.status(500).render('error', { message: 'Error al cargar la publicación' }); }
});

app.post('/post/:id/comments', requireAuth, async (req, res) => {
    try {
        const { text } = req.body;
        const post = await Post.findById(req.params.id);
        if (!post) return res.status(404).json({ success: false, message: "Post no encontrado" });

        const comment = {
            userId: req.session.userId,
            text: text
        };

        post.comments.push(comment);
        await post.save();

        const newComment = post.comments[post.comments.length - 1];
        const populatedComment = await newComment.populate('userId', 'username profilePic');

        res.json({ success: true, comment: populatedComment });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Error al añadir comentario" });
    }
});


app.post('/post/:id/like', requireAuth, async (req, res) => {
    try {
        const post = await Post.findById(req.params.id);
        const userId = req.session.userId;
        const index = post.likes.indexOf(userId);
        if (index > -1) { post.likes.splice(index, 1); } else { post.likes.push(userId); }
        await post.save();
        res.json({ success: true, likes: post.likes.length, liked: index === -1 });
    } catch (err) { res.status(500).json({ success: false, message: "Error en el servidor" }); }
});
app.post('/post/:id/boost', requireAuth, isPostOwner, async (req, res, next) => {
    try {
        const { duration, color, emoji } = req.body;
        const costs = { '1': 80, '10': 500 };
        const cost = costs[duration];
        if (!cost) throw new Error("Duración no válida.");
        const user = await User.findById(req.session.userId);
        if (user.tpysBalance < cost) throw new Error("No tienes suficientes TPYS.");
        user.tpysBalance -= cost;
        const post = res.locals.post;
        const now = new Date();
        const boostStartDate = post.boostedUntil && post.boostedUntil > now ? post.boostedUntil : now;
        post.boostedUntil = new Date(boostStartDate.getTime() + parseInt(duration) * 24 * 60 * 60 * 1000);
        post.boostOptions = { color, emoji };
        await user.save();
        await post.save();
        res.redirect(`/anuncio/${req.params.id}`);
    } catch (err) { next(err); }
});
app.post('/buy-video/:id', requireAuth, async (req, res, next) => {
    const dbSession = await mongoose.startSession();
    dbSession.startTransaction();
    try {
        const post = await Post.findById(req.params.id).session(dbSession);
        const buyer = await User.findById(req.session.userId).session(dbSession);
        const seller = await User.findById(post.userId).session(dbSession);
        if (!post || post.type !== 'video') throw new Error('Esta publicación no es un video o no existe.');
        if (buyer._id.equals(seller._id)) throw new Error('No puedes comprar tu propio contenido.');
        if (buyer.tpysBalance < post.price) throw new Error('No tienes suficientes TPYS para esta compra.');
        if (buyer.purchasedVideos.includes(post._id)) throw new Error('Ya has comprado este video.');
        const price = post.price;
        const platformFee = price * 0.45;
        const netEarning = price - platformFee;
        buyer.tpysBalance -= price;
        seller.tpysBalance += netEarning;
        buyer.purchasedVideos.push(post._id);
        post.salesCount += 1;
        await buyer.save({ session: dbSession });
        await seller.save({ session: dbSession });
        await post.save({ session: dbSession });
        const transaction = new Transaction({ sellerId: seller._id, buyerId: buyer._id, postId: post._id, amount: price, platformFee, netEarning });
        await transaction.save({ session: dbSession });
        await dbSession.commitTransaction();
        res.redirect(`/post/${post._id}`);
    } catch (err) {
        await dbSession.abortTransaction();
        next(err);
    } finally {
        dbSession.endSession();
    }
});
app.get('/add-funds', requireAuth, (req, res) => res.render('add-funds', { success: null }));
app.post('/add-funds', requireAuth, async (req, res, next) => {
    try {
        const amount = parseInt(req.body.amount, 10);
        if (isNaN(amount) || amount <= 0) throw new Error('Cantidad inválida');
        await User.findByIdAndUpdate(req.session.userId, { $inc: { tpysBalance: amount } });
        res.render('add-funds', { success: `¡Se han añadido ${amount} TPYS a tu cuenta!` });
    } catch(err) { next(err); }
});
app.get('/my-videos', requireAuth, async (req, res) => {
    const user = await User.findById(req.session.userId).populate({ path: 'purchasedVideos', model: 'Post', populate: { path: 'userId', model: 'User', select: 'username' }});
    res.render('my-videos', { videos: user.purchasedVideos });
});
app.get('/dashboard', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const sales = await Transaction.find({ sellerId: userId }).populate('postId', 'file price');
    const myVideos = await Post.find({ userId: userId, type: 'video' });
    const totalNetEarnings = sales.reduce((sum, t) => sum + t.netEarning, 0);
    res.render('dashboard', { totalNetEarnings, myVideos, TPYS_TO_GS_RATE });
});
app.get('/payout-info', requireAuth, (req, res) => res.render('payout-info'));

// =============================================
// MANEJADOR DE ERRORES
// =============================================
app.use((req, res, next) => {
  res.status(404).render('error', { message: 'Página no encontrada (404)' });
});
app.use((err, req, res, next) => {
  console.error("❌ ERROR FINAL CAPTURADO:", err);
  res.status(500).render('error', { message: err.message || 'Error interno del servidor (500)' });
});

// =============================================
// INICIAR SERVIDOR
// =============================================
app.listen(PORT, () => {
  console.log(`🚀 Servidor TentacionPY corriendo en http://localhost:${PORT}`);
});