export default {
  branches: ["main"],
  packages: [
    {
      name: "hoocloak",
      path: ".",
      type: "version-file",
      manifest: "internal/version/version",
      changelog: "CHANGELOG.md",
      scopes: ["hoocloak", "docker", "ghcr", "image", "release"],
      dependencies: [],
    },
  ],
  hooks: {
    afterVersion: [],
  },
  github: {
    releases: true,
  },
};
