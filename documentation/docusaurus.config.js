const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').DocusaurusConfig} */
module.exports = {
  title: 'IOTA Streams',
  tagline: 'Official IOTA Streams Software',
  url: 'https://wiki.iota.org/',
  baseUrl: '/streams/',
  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'throw',
  favicon: '/img/logo/favicon.ico',
  organizationName: 'iotaledger', // Usually your GitHub org/user name.
  projectName: 'streams', // Usually your repo name.
  stylesheets: [
    'https://fonts.googleapis.com/css?family=Material+Icons',
  ],
  themeConfig: {
    colorMode: {
      defaultMode: "dark",
    },
    navbar: {
      title: 'Streams',
      logo: {
        alt: 'IOTA',
        src: '/img/logo/Logo_Swirl_Dark.png',
      },
      items: [
        {
          type: 'doc',
          docId: 'welcome',
          position: 'left',
          label: 'Documentation',
        },
        {
          href: 'https://github.com/iotaledger/streams',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Welcome',
              to: '/docs/welcome',
            },
            {
              label: 'Overview',
              to: '/docs/overview',
            },
            {
              label: 'Libraries',
              to: '/docs/libraries/overview',
            },
            {
              label: 'Specification',
              to: '/docs/specs',
            },
            {
              label: 'Contribute',
              to: '/docs/contribute',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/iotaledger/streams',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} IOTA Foundation, Built with Docusaurus.`,
    },
    prism: {
      additionalLanguages: ['rust'],
      theme: lightCodeTheme,
      darkTheme: darkCodeTheme,
    },
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          editUrl:
              'https://github.com/iotaledger/streams/tree/dev/documentation/',
        },
        theme: {
          customCss: require.resolve('./src/css/iota.css'),
        },
      },
    ],
  ],
  plugins: [
  ],
};