'use strict';

const { createApp } = require('./app');

const port = Number(process.env.PORT || 8080);

createApp().listen(port, '0.0.0.0', () => {
  console.log(`supplier-portal listening on :${port}`);
});
