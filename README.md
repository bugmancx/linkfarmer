# linkfarmer

Discord bot that monitors channels for URLs and creates jDownloader crawljobs.

## Quick Start

```bash
docker-compose up -d
```

Create a `.env` file with your configuration.

## Configuration

### Required

| Variable | Description |
|----------|-------------|
| `DISCORD_BOT_TOKEN` | Your Discord bot token |
| `DISCORD_CHANNELS` | Comma-separated channel IDs (e.g., `1234567890,0987654321`) |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `JDOWNLOADER` | `false` | Enable jDownloader crawljob creation (`true`/`false`) |
| `JDOWNLOADER_CRAWLJOB_PATH` | `/data/crawljobs` | Directory for crawljob files |
| `JDOWNLOADER_OUTPUT_PATH` | `/data/output` | Download destination |
| `URL_LOG` | `/data/log/url_log.txt` | Path to URL log file |
| `EXCLUDED_DOMAINS` | (empty) | Comma-separated domains to skip (e.g., `instagram.com,twitter.com`) |
| `INPUT_FILE` | `/data/input/input_urls.txt` | Batch input file path |

## Setup

Create `.env` file:
```
DISCORD_BOT_TOKEN=your_token_here
DISCORD_CHANNELS=channel_id_1,channel_id_2
JDOWNLOADER=true
JDOWNLOADER_CRAWLJOB_PATH=/data/crawljobs
JDOWNLOADER_OUTPUT_PATH=/output/linkfarmer
EXCLUDED_DOMAINS=instagram.com,twitter.com
```

Docker Compose:
```yaml
services:
  discord-bot:
    container_name: link-farmer
    build:
      context: .
    env_file: .env
    volumes:
      - ./data/log:/data/log
      - jdownloader_crawljobs:/data/crawljobs
    restart: unless-stopped

volumes:
  jdownloader_crawljobs:
```

## How It Works

1. Bot listens to specified Discord channels
2. When a URL is posted, extracts and validates it
3. Logs the URL to `/data/log/url_log.txt`
4. If jDownloader enabled, creates a crawljob file
5. Domain exclusions prevent certain URLs from processing

## Discord Setup

1. Create bot at [Discord Developer Portal](https://discord.com/developers/applications)
2. Copy bot token to `DISCORD_BOT_TOKEN`
3. Enable **Message Content Intent** in bot settings
4. Get channel IDs (Developer Mode → right-click channel → Copy ID)
5. Add bot to your server

## jDownloader Integration

When `JDOWNLOADER=true`, creates `.crawljob` JSON files in the watch directory.

With jDownloader service:
```yaml
services:
  jdownloader:
    image: jdownloader/jdownloader:latest
    volumes:
      - jdownloader_config:/config
      - jdownloader_crawljobs:/watch/crawljobs
      - jdownloader_output:/output

  discord-bot:
    build:
      context: .
    env_file: .env
    depends_on:
      - jdownloader
    volumes:
      - ./data/log:/data/log
      - jdownloader_crawljobs:/data/crawljobs
      - jdownloader_output:/output/linkfarmer

volumes:
  jdownloader_config:
  jdownloader_crawljobs:
  jdownloader_output:
```

## Batch Processing

Place URLs in `/data/input/input_urls.txt`:
```
https://example.com/file1.zip
https://example.com/file2.zip
Check this: https://download.site/resource.mp4
```

Bot processes and clears the file after.
