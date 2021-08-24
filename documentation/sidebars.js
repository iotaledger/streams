/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

module.exports = {
    docs: [
        {
            type: 'doc',
            id: 'welcome',
        }, {
            type: 'doc',
            id: 'overview/README',
            label: 'Overview'
        }, {
            type: 'category',
            label: 'Libraries',
            collapsed: false,
            items: [
                {
                    type: 'category',
                    label: 'Rust',
                    items:
                        [
                            {
                                type: 'doc',
                                id: 'libraries/rust/README',
                                label: 'Overview'
                            }, {
                            type: 'doc',
                            id: 'libraries/rust/examples',
                            label: 'Examples'
                        }, {
                            type: 'doc',
                            id: 'libraries/rust/getting_started',
                            label: 'Getting Started'
                        }, {
                            type: 'doc',
                            id: 'libraries/rust/api_reference',
                            label: 'API Reference'
                        }, {
                            type: 'doc',
                            id: 'libraries/rust/troubleshooting',
                            label: 'Troubleshooting'
                        },],
                },
                {
                    type: 'category',
                    label: 'WASM',
                    items:
                        [
                            {
                                type: 'doc',
                                id: 'libraries/wasm/README',
                                label: 'Overview'
                            }, {
                            type: 'doc',
                            id: 'libraries/wasm/examples',
                            label: 'Examples'
                        }, {
                            type: 'doc',
                            id: 'libraries/wasm/getting_started',
                            label: 'Getting Started'
                        }, {
                            type: 'doc',
                            id: 'libraries/wasm/api_reference',
                            label: 'API Reference'
                        }, {
                            type: 'doc',
                            id: 'libraries/wasm/troubleshooting',
                            label: 'Troubleshooting'
                        },],
                },

                {
                    type: 'category',
                    label: 'C',
                    items:
                        [
                            {
                                type: 'doc',
                                id: 'libraries/c/README',
                                label: 'Overview'
                            }, {
                            type: 'doc',
                            id: 'libraries/c/examples',
                            label: 'Examples'
                        }, {
                            type: 'doc',
                            id: 'libraries/c/getting_started',
                            label: 'Getting Started'
                        }, {
                            type: 'doc',
                            id: 'libraries/c/api_reference',
                            label: 'API Reference'
                        }, {
                            type: 'doc',
                            id: 'libraries/c/troubleshooting',
                            label: 'Troubleshooting'
                        },],
                },
            ],
        }, {
            type: 'doc',
            id: 'specs/README',
            label: 'Specification'
        }, {
            type: 'doc',
            id: 'contribute',
            label: 'Contribute'
        },
    ],
};
