---
layout: post
title:  "Capturing Terminal Output to Video"
date:   2026-04-02
categories:
- tools
comments: true
---

My terminal recording tool of choice is [asciinema](https://asciinema.org/). You can use asciinema to publish your recordings. For those more interested in controlling their content (like me), I'll show how to create MP4 videos with open source tools.

Why do I like asciinema?

- Easy to use, scriptable
- You can let it run in a terminal and not worry about pop-ups and such being recorded
- Captures as text
- Text can be extracted and used in other tools
- Replayable to the terminal, optionally with different rows and columns
- The `agg` command will convert to an animated GIF and compress wait time

## asciinema

The asciinema `--help` and website has full documentation, I'll describe the commands I use the most.

Recording:

```shell
asciinema rec terminal.cast
```

This command will convert to a text file to read like a log.

```shell
asciinema convert --output-format txt terminal.cast terminal.txt
```

## agg: asciinema to GIF

The [agg](https://github.com/asciinema/agg) tool converts a cast to an animated GIF. It can compress wait time, which I always use. The following command compresses wait time to 2 seconds.

```shell
agg --idle-time-limit 2 terminal.cast terminal.gif
```

## Converting to MP4

Animated GIFs work and are fairly space efficient. However, recordings are typically in video formats. I experimented with [ffmpeg](https://ffmpeg.org/) to find the best configuration to convert to MP4. MP4 isn't required, but it is commonly supported.

The `ffmpeg` command I've landed on:

```shell
ffmpeg -i terminal.gif -ignore_loop 0 -movflags +faststart -pix_fmt yuv420p -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" -c:v libx265 -crf 28 -preset veryslow terminal.mp4
```

Options:
 
- `-ignore_loop 0`: ignore GIF loop
- `-movflags +faststart`: streamable MP4 (plays before fully downloaded)
- `-pix_fmt yuv420p`: maximize compatibility with players/devices
- `-vf "scale=trunc(iw/2)*2:trunc(ih/2)*2"`: ensures even dimensions
- `-c:v libx265`: encode with H.265/HEVC
- `-crf 28`: quality (lower = better); 18–28 typical (23 default)
- `-preset veryslow`: speed vs compression (ultrafast → veryslow)

The `-crf` option is a tradeoff between quality and size. Terminal recordings do not need as much data, so `28` is a good value. I've found my MP4 files are smaller than the GIF using `-crf 28`. If the quality isn't what you want, try `23`.

## Example

### Animated GIF

![asciinema terminal recording](/assets/video/ginandjuice-kimi2.5-web_recon.gif)

### Video

<video controls width="100%">
  <source src="/assets/video/ginandjuice-kimi2.5-web_recon.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

## Size Comparisons

For a larger recording, I did some experiments to see what the file size would be. Quality is looks the same to me in all of these. I included the H.264 codec because it is older and more widely supported, but it isn't as efficient.

| Codec | CRF | Preset   | Size  |
|-------|-----|----------|-------|
| GIF   |     |          | 19 MB |
| H.264 | 18  | medium   | 38 MB |
| H.264 | 23  | veryslow | 24 MB |
| H.264 | 28  | veryslow | 18 MB |
| H.265 | 23  | veryslow | 15 MB |
| H.265 | 28  | veryslow | 11 MB |

The importance of using a video file is compatibility and user experience. Not all applications will display the animated GIF properly. An animated GIF doesn't give the user control to pause or navigate through the video.

If you only want to show your recording on a web browser, GIF can be a good option. If you want to distribute the file otherwise or let the user navigate, I recommend converting to MP4.
