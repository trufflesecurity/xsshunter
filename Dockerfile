FROM node:16-bullseye

RUN mkdir /app/
RUN mkdir /app/payload-fire-images
WORKDIR /app/
RUN npm install pm2 -g
RUN apt update; apt install -y libstdc++6

COPY --chown=node:node front-end/ /app/front-end/
WORKDIR /app/front-end/
RUN npm install
RUN npm run-script build

WORKDIR /app/
COPY --chown=node:node package.json /app/
COPY --chown=node:node package-lock.json /app/
RUN npm install

COPY --chown=node:node server.js /app/
COPY --chown=node:node probe.js /app/
COPY --chown=node:node constants.js /app/
COPY --chown=node:node notification.js /app/
COPY --chown=node:node database.js /app/
COPY --chown=node:node api.js /app/
COPY --chown=node:node app.js /app/
COPY --chown=node:node utils.js /app/
COPY --chown=node:node docker-entrypoint.sh /app/
RUN chown -R node:node /app/payload-fire-images
RUN chmod +x /app/docker-entrypoint.sh
COPY --chown=node:node templates /app/templates

USER node

# Start the server
ENTRYPOINT ["/app/docker-entrypoint.sh"]
