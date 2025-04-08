FROM ghcr.io/foundry-rs/foundry

WORKDIR /anvil

EXPOSE 8545

ENTRYPOINT anvil -b 2 --host 0.0.0.0

# FROM ghcr.io/foundry-rs/foundry

# WORKDIR /anvil

# ARG PRIVATE_KEY
# ENV PRIVATE_KEY=$PRIVATE_KEY

# # Copy contracts and deployment scripts
# COPY contracts/ ./contracts/
# COPY foundry.toml .
# COPY lib/ ./lib/
# COPY remappings.txt .

# # Deploy the contracts
# COPY dockerfiles/scripts/anvil-run.sh anvil-run.sh

# USER root
# RUN chmod +x anvil-run.sh

# EXPOSE 8545

# ENTRYPOINT sh anvil-run.sh