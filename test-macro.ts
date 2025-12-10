import { Elysia } from 'elysia';
import { FlashAuth, flashAuth } from './src/index.ts';

const auth = new FlashAuth({
  secret: FlashAuth.generateSecret(),
});

const app = new Elysia()
  .use(flashAuth(auth))
  .get('/test', (context) => {
    console.log('Context keys:', Object.keys(context));
    console.log('flashAuth exists?', 'flashAuth' in context);
    console.log('flashAuth value:', context.flashAuth);
    return { context: Object.keys(context) };
  })
  .listen(3001);

console.log('Test app running on http://localhost:3001');
console.log('Try: curl http://localhost:3001/test');
