// index.js
// Jednostavni entry point koji samo digne server iz server.js

require('dotenv').config();

console.log('Bootstrapping Tinder backend...');

require('./server');
