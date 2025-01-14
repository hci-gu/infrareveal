#!/bin/bash

VERSION=1.23.0 # Specify the desired Go version
ARCH=aarch64 # arm64 for 64-bit OS

## Download the latest version of Golang
echo "Downloading Go $VERSION"
wget https://dl.google.com/go/go$VERSION.linux-$ARCH.tar.gz -O /tmp/go$VERSION.linux-$ARCH.tar.gz
echo "Downloading Go $VERSION completed"

## Create the target directory if it doesn't exist
TARGET_DIR="$HOME/.local/share"
if [ ! -d "$TARGET_DIR" ]; then
    echo "Creating directory $TARGET_DIR"
    mkdir -p "$TARGET_DIR"
fi

## Extract the archive
echo "Extracting Go $VERSION..."
tar -C "$TARGET_DIR" -xzf /tmp/go$VERSION.linux-$ARCH.tar.gz
echo "Extraction complete"

## Detect the user's shell and add the appropriate path variables
SHELL_TYPE=$(basename "$SHELL")

if [ "$SHELL_TYPE" = "zsh" ]; then
    echo "Found ZSH shell"
    SHELL_RC="$HOME/.zshrc"
elif [ "$SHELL_TYPE" = "bash" ]; then
    echo "Found Bash shell"
    SHELL_RC="$HOME/.bashrc"
elif [ "$SHELL_TYPE" = "fish" ]; then
    echo "Found Fish shell"
    SHELL_RC="$HOME/.config/fish/config.fish"
else
    echo "Unsupported shell: $SHELL_TYPE"
    exit 1
fi

echo 'export GOPATH=$HOME/.local/share/go' >> "$SHELL_RC"
echo 'export PATH=$HOME/.local/share/go/bin:$PATH' >> "$SHELL_RC"

## Reload the shell configuration
if [ "$SHELL_TYPE" = "fish" ]; then
    source "$SHELL_RC" 2>/dev/null || echo "Restart your shell or run: source $SHELL_RC"
else
    source "$SHELL_RC" 2>/dev/null || echo "Restart your shell or run: source $SHELL_RC"
fi

## Verify the installation
if [ -x "$(command -v go)" ]; then
    INSTALLED_VERSION=$(go version | awk '{print $3}')
    if [ "$INSTALLED_VERSION" == "go$VERSION" ]; then
        echo "Go $VERSION is installed successfully."
    else
        echo "Installed Go version ($INSTALLED_VERSION) doesn't match the expected version (go$VERSION)."
    fi
else
    echo "Go is not found in the PATH. Make sure to add Go's bin directory to your PATH."
fi

## Clean up
echo "Cleaning up..."
rm /tmp/go$VERSION.linux-$ARCH.tar.gz
echo "Cleanup complete."
