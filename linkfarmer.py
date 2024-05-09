import os
import re
import nextcord
import logging
import json
from nextcord.ext import commands
from datetime import datetime

# Define environment variables for bot configuration
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
URL_LOG = os.getenv('LOG_FILE', '/data/log/url_log.txt')
JDOWNLOADER = os.getenv('JDOWNLOADER', 'false')
JDOWNLOADER_CRAWLJOB_PATH = os.getenv('JDOWNLOADER_CRAWLJOB_PATH', '/data/crawljobs')
JDOWNLOADER_OUTPUT_PATH = os.getenv('JDOWNLOADER_OUTPUT_PATH', '/data/output')  # Default to '/output' if not provided
DISCORD_CHANNELS = os.getenv('DISCORD_CHANNELS', '')
EXCLUDED_DOMAINS = os.getenv('EXCLUDED_DOMAINS', '')

# Convert excluded domains from string to a set
excluded_domains = set(domain.strip() for domain in EXCLUDED_DOMAINS.split(',') if domain.strip())

# Create bot with appropriate intents
intents = nextcord.Intents.default()
intents.messages = True
intents.message_content = True  # Enable message content intent to access message content
bot = commands.Bot(command_prefix='!', intents=intents)

# Convert the channel list to a set of integers (channel IDs)
monitored_channels = set(int(cid) for cid in DISCORD_CHANNELS.split(',') if cid.strip().isdigit())

# Set up logging to console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@bot.event
async def on_ready():
    logging.info(f'Logged in as {bot.user}')

def process_url(url, username, uid):
    
    # Check if the URL domain is excluded
    domain = re.search(r'https?://([^/]+)', url).group(1)
    if domain in excluded_domains:
        logging.info(f'URL {url} is excluded and will not be processed.')
        return  # Skip processing if the domain is excluded

    log_entry = f'{datetime.now()} - {username} ({uid}): {url}'

    # Log URL to url_log.txt file
    with open(URL_LOG, 'a') as file:
        file.write(f'{log_entry}\n')

    if JDOWNLOADER.lower() == 'true':
        # Create crawljob file name with username prefix
        filename_url = re.sub(r'[^\w\s\-\.]', '_', url)

        # Create crawljob file name with username prefix
        crawljob_filename = f'{username}-{filename_url}.crawljob'

        logging.info(f'Creating crawljob file {crawljob_filename} for URL {url}')

        # Construct crawljob content
        crawljob_content = [{
            "text": url,
            "downloadFolder": JDOWNLOADER_OUTPUT_PATH,
            "autoStart": "TRUE",
            "autoConfirm": "TRUE",
            "enabled": "TRUE",
            "packageName": os.path.basename(url),
            "overwritePackagizerEnabled": True
        }]

        # Write crawljob content to file
        crawljob_file = os.path.join(JDOWNLOADER_CRAWLJOB_PATH, crawljob_filename)
        os.makedirs(JDOWNLOADER_CRAWLJOB_PATH, exist_ok=True)
        with open(crawljob_file, 'w') as file:
            file.write(json.dumps(crawljob_content, indent=4))
            logging.info(f'URL {url} added to crawljob file {crawljob_file}')

@bot.event
async def on_message(message):
    if message.author == bot.user or message.channel.id not in monitored_channels:
        return

    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F])|[#])+', message.content)
    if urls:
        for url in urls:
            process_url(url, message.author.name, message.author.id)

    # Log message content to console
    logging.info(f'User {message.author.name} in channel {message.channel.name} posted: {message.content}')

bot.run(DISCORD_BOT_TOKEN)
