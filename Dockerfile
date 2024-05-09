# Stage 1: Build Environment
FROM python:3.10-slim as builder

# Set the working directory in the build stage
WORKDIR /build

# Copy only the requirements file and install dependencies
COPY requirements.txt .
RUN python -m venv venv
RUN . venv/bin/activate && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY linkfarmer.py .

# Stage 2: Runtime Environment
FROM python:3.10-slim

# Set the working directory in the container to /app
WORKDIR /app

# Create a non-root user and group
RUN groupadd -g 911 linkfarmer && useradd -u 911 -g 911 -m linkfarmer

# Copy virtual environment from the builder stage
COPY --from=builder /build/venv ./venv
COPY --from=builder /build/linkfarmer.py .

# Define environment variables for bot configuration
ENV DISCORD_BOT_TOKEN=YourBotTokenHere
ENV URL_LOG=/data/log/url_log.txt
ENV JDOWNLOADER=false
ENV JDOWNLOADER_CRAWLJOB_PATH=/data/crawljobs
ENV DOWNLOAD_DIRECTORY=/data/output
ENV EXCLUDED_DOMAINS=
ENV PUID=911
ENV PGID=911

# Make directories for logs and crawljobs
RUN mkdir -p /data/log /data/crawljobs

# Set the ownership of /data to the specified user and group
RUN chown -R linkfarmer:linkfarmer /data

# Run linkfarmer.py when the container launches using the virtual environment
USER linkfarmer
CMD ["venv/bin/python", "linkfarmer.py"]
