FROM node:20-slim
ENV OPENAI_API_KEY=""
ENV ANTHROPIC_BASE_URL=https://api.anthropic.com
RUN npm install -g @anthropic-ai/claude-code
COPY . .
CMD ["node", "dist/index.js"]
