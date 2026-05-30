const { Telegraf } = require('telegraf');
const axios = require('axios');

const GROUP_BOT_TOKEN = process.env.GROUP_BOT_TOKEN;
const WEBSITE_API = process.env.WEBSITE_API || 'http://localhost:3000/api/group-message';
const GROUP_BOT_SECRET = process.env.GROUP_BOT_SECRET || 'default-secret';
const WALLET_BOT_ID = process.env.WALLET_BOT_ID;
const GROUP_CHAT_ID = parseInt(process.env.GROUP_CHAT_ID);

if (!GROUP_BOT_TOKEN) {
  console.error('ERROR: GROUP_BOT_TOKEN is required');
  process.exit(1);
}

const bot = new Telegraf(GROUP_BOT_TOKEN);

// Deduplication store
const processedMessages = new Set();
const MAX_STORED_MESSAGES = 10000;

// ============================================
// MESSAGE HANDLER
// ============================================

bot.on('message', async (ctx) => {
  const msg = ctx.message;

  // Deduplication
  if (processedMessages.has(msg.message_id)) {
    return;
  }
  processedMessages.add(msg.message_id);

  // Cleanup old message IDs to prevent memory leak
  if (processedMessages.size > MAX_STORED_MESSAGES) {
    const iterator = processedMessages.values();
    processedMessages.delete(iterator.next().value);
  }

  // Only process messages from target group
  const chatId = msg.chat.id;

  if (chatId !== GROUP_CHAT_ID) {
    console.log(`[SKIP] Chat ${chatId} != target ${GROUP_CHAT_ID}`);
    return;
  }

  // Build payload
  const messageData = {
    messageId: msg.message_id,
    from: {
      id: msg.from?.id,
      username: msg.from?.username,
      firstName: msg.from?.first_name,
      lastName: msg.from?.last_name,
      isBot: msg.from?.is_bot,
    },
    text: msg.text || msg.caption || '',
    chat: {
      id: chatId,
      title: msg.chat?.title,
      type: msg.chat?.type,
    },
    date: msg.date,
    replyTo: msg.reply_to_message ? {
      messageId: msg.reply_to_message.message_id,
      text: msg.reply_to_message.text || msg.reply_to_message.caption || '',
      from: msg.reply_to_message.from,
    } : null,
    entities: msg.entities || msg.caption_entities || [],
  };

  const logPrefix = `[${new Date().toISOString()}]`;
  const sender = msg.from?.username || msg.from?.id || 'unknown';
  const preview = messageData.text.substring(0, 80).replace(/\n/g, ' ');
  console.log(`${logPrefix} From ${sender}: ${preview}...`);

  try {
    const response = await axios.post(WEBSITE_API, messageData, {
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Bot-Secret': GROUP_BOT_SECRET,
      },
      timeout: 10000,
    });

    console.log(`${logPrefix} Website action: ${response.data.action || 'OK'}`);

  } catch (error) {
    console.error(`${logPrefix} Forward failed: ${error.message}`);

    // Retry once
    setTimeout(async () => {
      try {
        await axios.post(WEBSITE_API, messageData, {
          headers: {
            'Content-Type': 'application/json',
            'X-Telegram-Bot-Secret': GROUP_BOT_SECRET,
          },
          timeout: 10000,
        });
        console.log(`${logPrefix} Retry successful`);
      } catch (retryError) {
        console.error(`${logPrefix} Retry failed: ${retryError.message}`);
      }
    }, 2000);
  }
});

// ============================================
// ERROR HANDLING
// ============================================

bot.catch((err, ctx) => {
  console.error(`Error for ${ctx.updateType}:`, err.message);
});

// ============================================
// LAUNCH
// ============================================

bot.launch()
  .then(() => {
    console.log('🤖 Group Bot started');
    console.log(`Target group: ${GROUP_CHAT_ID}`);
    console.log(`Wallet bot ID: ${WALLET_BOT_ID || 'ALL MESSAGES'}`);
    console.log(`Website API: ${WEBSITE_API}`);
  })
  .catch(err => {
    console.error('Failed to start:', err);
    process.exit(1);
  });

process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));

// Heartbeat
setInterval(() => {
  console.log(`[${new Date().toISOString()}] Heartbeat | Processed: ${processedMessages.size}`);
}, 5 * 60 * 1000);
