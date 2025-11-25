import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'NannyAgent',
      items: [
        'CONFIGURATION',
        'INSTALLATION',
        'GORELEASER_BUILD',
        'EBPF_README',
        'EBPF_INTEGRATION_COMPLETE',
        'EBPF_SECURITY_IMPLEMENTATION',
        'EBPF_TENSORZERO_INTEGRATION',
        'TENSORZERO_SYSTEM_PROMPT',
        'writing-documentation',
      ],
    },
  ],
};

export default sidebars;
