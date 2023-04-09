# Krypton
JavaScript Wrapper for the Web Crypto API

### Installation:
```bash
npm install @d1g1tal/krypton --save
```

### Usage:
```javascript
import Krypton from '@d1g1tal/krypton';

const krypton = new Krypton();
const data = 'Hello World!';
const encrypted = await krypton.encrypt(data);
const decrypted = await krypton.decrypt(encrypted);

console.log(decrypted); // Hello World!
```