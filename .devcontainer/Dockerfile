# Use the official PowerShell image as a parent image
FROM mcr.microsoft.com/powershell:7.3.0-debian-11

# Install additional tools if needed
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /workspace

# Copy the current directory contents into the container at /workspace
COPY . .

# Ensure PowerShell command is available
CMD [ "pwsh" ]
