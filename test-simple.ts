import { Elysia } from 'elysia';

const testPlugin = new Elysia({ name: 'test' })
  .derive(() => {
    console.log('derive called!');
    return {
      myContext: { value: 'test' }
    };
  });

const app = new Elysia()
  .use(testPlugin)
  .get('/test', (context) => {
    console.log('Context keys:', Object.keys(context));
    console.log('myContext exists?', 'myContext' in context);
    return { keys: Object.keys(context) };
  })
  .listen(3002);

console.log('Simple test app running on http://localhost:3002');
