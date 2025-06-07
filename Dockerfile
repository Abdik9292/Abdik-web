FROM node:20
# Install dependencies
RUN npm install

# Expose the app port
EXPOSE 3000

# Start the application
CMD ["node", "index.js"]
