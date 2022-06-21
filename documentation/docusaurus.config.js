const path = require('path');

module.exports = {
  plugins: [
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'streams',
        path: path.resolve(__dirname, 'docs'),
        routeBasePath: 'streams',
        sidebarPath: path.resolve(__dirname, 'sidebars.js'),
        editUrl: 'https://github.com/iotaledger/streams/edit/develop/documentation',
        remarkPlugins: [require('remark-code-import'), require('remark-import-partial')],
        versions: {
          current: {
            label: 'IOTA',
            badge: true
          },
        },
      }
    ],
  ],
  staticDirectories: [path.resolve(__dirname, 'static')],
};
