import { Elysia, t } from 'elysia';
import { FlashAuth, flashAuth } from './src/index.ts';

const auth = new FlashAuth({
  secret: FlashAuth.generateSecret(),
});

const app = new Elysia()
  .use(flashAuth(auth))
  .post('/login', async () => {
    const token = await auth
      .createToken()
      .subject('user:123')
      .claim('email', 'test@example.com')
      .roles(['user'])
      .expiresIn('1h')
      .build();
    return { token };
  })
  .get('/test-context', (ctx) => {
    console.log('Context keys:', Object.keys(ctx));
    console.log('flashAuth exists:', 'flashAuth' in ctx);
    console.log('flashAuth value:', ctx.flashAuth);
    if (ctx.flashAuth) {
      console.log('claims:', ctx.flashAuth.claims);
      console.log('token:', ctx.flashAuth.token);
    }
    return { flashAuth: ctx.flashAuth };
  })
  .get('/test-macro', (ctx) => {
    return { claims: ctx.flashAuth?.claims };
  }, {
    isAuth: true
  })
  .listen(3005);

console.log('Debug app running on http://localhost:3005');
