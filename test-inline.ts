import { Elysia } from 'elysia';

const app = new Elysia()
  .derive(() => {
    console.log('derive called!');
    return {
      myContext: { value: 'test' }
    };
  })
  .get('/test', (context) => {
    console.log('Context keys:', Object.keys(context));
    console.log('myContext exists?', 'myContext' in context);
    console.log('myContext value:', context.myContext);
    return { keys: Object.keys(context), has: 'myContext' in context };
  })
  .listen(3003);

console.log('Inline test app running on http://localhost:3003');
