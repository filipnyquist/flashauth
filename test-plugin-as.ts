import { Elysia } from 'elysia';

const testPlugin = () => new Elysia({ name: 'test' })
  .derive(() => {
    console.log('derive called in plugin!');
    return {
      myContext: { value: 'test' }
    };
  })
  .as('plugin');

const app = new Elysia()
  .use(testPlugin())
  .get('/test', (context) => {
    console.log('Context keys:', Object.keys(context));
    console.log('myContext exists?', 'myContext' in context);
    console.log('myContext value:', context.myContext);
    return { keys: Object.keys(context), has: 'myContext' in context };
  })
  .listen(3004);

console.log('Plugin with .as() test app running on http://localhost:3004');
