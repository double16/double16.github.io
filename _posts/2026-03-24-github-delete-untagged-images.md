---
layout: post
title:  "GitHub Actions: Delete untagged images"
date:   2026-03-24
categories:
- docker
comments: true
---

TIL of a GitHub action that deletes untagged images from the container registry. Using CI workflows you can end up with a lot of untagged images in your registry. Here is a snippet of how to clean those up after a successful build.

```yaml
  - uses: actions/delete-package-versions@v5
    with:
      package-name: ${{ github.event.repository.name }}
      package-type: 'container'
      min-versions-to-keep: 10
      delete-only-untagged-versions: 'true'
```

Tweak to your liking. The `package-name` value depends on how your name your image. Most of my repos that produce an image produce one. I name it the same as the repo.

Look at the [GitHub action docs](https://github.com/actions/delete-package-versions) for more info.
