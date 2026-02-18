---
name: mobile-communication
description: "Real-time communication features for mobile apps — chat, push notifications, realtime subscriptions, and multi-channel messaging. Use when: (1) Building chat UIs, (2) Setting up push notifications, (3) Implementing Supabase realtime, (4) Routing notifications across channels."
consumes_modules:
  - mobile-chat
  - expo-push-notifications
  - supabase-realtime
  - omni-channel-core
---

# Mobile Communication

> Real-time communication features for mobile apps — chat, push notifications, realtime subscriptions, and multi-channel messaging. Use when: building in-app chat, setting up push notifications with Expo, subscribing to Supabase realtime changes, or routing messages across push/email/SMS/in-app channels.

---

## Module Dependencies

| Module | What It Provides |
|--------|-----------------|
| `mobile-chat` | Chat UI components, message threading, typing indicators, read receipts, media messages |
| `expo-push-notifications` | Expo push token registration, notification handlers, badge management, notification categories |
| `supabase-realtime` | Realtime subscriptions, presence tracking, broadcast channels, database change listeners |
| `omni-channel-core` | Channel routing engine, notification preferences, delivery tracking, fallback chains |

---

## Overview

This skill provides a complete communication stack for React Native/Expo mobile apps. The 4 modules cover the full spectrum from UI-level chat components to infrastructure-level message routing:

- **Presentation**: `mobile-chat` provides the visual chat experience
- **Transport (Push)**: `expo-push-notifications` delivers messages when the app is backgrounded
- **Transport (Realtime)**: `supabase-realtime` powers live updates when the app is foregrounded
- **Orchestration**: `omni-channel-core` routes messages to the right channel based on user preferences and delivery rules

All examples use React Native with Expo SDK and TypeScript.

---

## 1. Chat UI

### Basic Chat Screen

```tsx
import {
  ChatContainer,
  MessageList,
  MessageInput,
  MessageBubble,
  TypingIndicator,
  useChatMessages,
} from 'mobile-chat';

export function ChatScreen({ conversationId, currentUser }) {
  const {
    messages,
    isLoading,
    hasMore,
    loadMore,
    sendMessage,
    markAsRead,
  } = useChatMessages(conversationId);

  useEffect(() => {
    // Mark messages as read when screen is focused
    markAsRead(conversationId);
  }, [messages.length]);

  return (
    <ChatContainer>
      <MessageList
        messages={messages}
        currentUserId={currentUser.id}
        onEndReached={loadMore}
        hasMore={hasMore}
        isLoading={isLoading}
        renderMessage={(message) => (
          <MessageBubble
            key={message.id}
            message={message}
            isOwn={message.senderId === currentUser.id}
            showAvatar={message.senderId !== currentUser.id}
            showTimestamp
            showReadReceipt
          />
        )}
        renderTypingIndicator={() => (
          <TypingIndicator users={typingUsers} />
        )}
      />
      <MessageInput
        onSend={(text) => sendMessage({ type: 'text', content: text })}
        onAttach={handleAttachment}
        placeholder="Type a message..."
        maxLength={2000}
      />
    </ChatContainer>
  );
}
```

### Message Types and Media

```tsx
import {
  MediaMessage,
  LocationMessage,
  ReplyMessage,
  MessageBubble,
} from 'mobile-chat';

function renderMessage(message) {
  switch (message.type) {
    case 'text':
      return <MessageBubble message={message} />;

    case 'image':
      return (
        <MediaMessage
          message={message}
          mediaType="image"
          thumbnailUri={message.thumbnailUrl}
          fullUri={message.mediaUrl}
          onPress={() => openImageViewer(message.mediaUrl)}
        />
      );

    case 'location':
      return (
        <LocationMessage
          message={message}
          latitude={message.latitude}
          longitude={message.longitude}
          label={message.locationLabel}
          onPress={() => openMaps(message.latitude, message.longitude)}
        />
      );

    case 'reply':
      return (
        <ReplyMessage
          message={message}
          originalMessage={message.replyTo}
        />
      );

    default:
      return <MessageBubble message={message} />;
  }
}
```

### Typing Indicators with Supabase Realtime

```tsx
import { useTypingStatus } from 'mobile-chat';
import { useRealtimePresence } from 'supabase-realtime';

export function useTypingIndicator(conversationId: string, currentUserId: string) {
  const { setTyping } = useTypingStatus();
  const { presenceState, track } = useRealtimePresence(`chat:${conversationId}`);

  // Broadcast typing status
  const onTypingChange = useCallback(
    (isTyping: boolean) => {
      track({
        user_id: currentUserId,
        is_typing: isTyping,
        typing_at: isTyping ? new Date().toISOString() : null,
      });
    },
    [currentUserId, track]
  );

  // Get other users who are typing
  const typingUsers = useMemo(() => {
    return Object.values(presenceState)
      .flat()
      .filter((p) => p.user_id !== currentUserId && p.is_typing)
      .map((p) => p.user_id);
  }, [presenceState, currentUserId]);

  return { typingUsers, onTypingChange };
}
```

---

## 2. Push Notifications

### Token Registration

```tsx
import {
  usePushNotifications,
  registerForPushNotifications,
  PushNotificationHandler,
} from 'expo-push-notifications';

export function NotificationSetup() {
  const { token, permission, requestPermission } = usePushNotifications();

  useEffect(() => {
    if (token) {
      // Send token to your backend
      api.registerPushToken({
        token: token.data,
        platform: Platform.OS,
        userId: currentUser.id,
      });
    }
  }, [token]);

  useEffect(() => {
    if (permission === 'undetermined') {
      requestPermission();
    }
  }, [permission]);

  return null; // Setup component, no UI
}
```

### Notification Handlers

```tsx
import {
  useNotificationReceived,
  useNotificationResponse,
  NotificationCategory,
  setNotificationCategories,
} from 'expo-push-notifications';

// Define notification categories with actions
setNotificationCategories([
  {
    identifier: NotificationCategory.MESSAGE,
    actions: [
      { identifier: 'reply', title: 'Reply', textInput: { placeholder: 'Type reply...' } },
      { identifier: 'mark_read', title: 'Mark Read' },
    ],
  },
  {
    identifier: NotificationCategory.REMINDER,
    actions: [
      { identifier: 'snooze', title: 'Snooze 1h' },
      { identifier: 'dismiss', title: 'Dismiss', destructive: true },
    ],
  },
]);

export function NotificationListener({ navigation }) {
  // Foreground notification
  useNotificationReceived((notification) => {
    const data = notification.request.content.data;

    // Show in-app notification banner instead of system notification
    showInAppBanner({
      title: notification.request.content.title,
      body: notification.request.content.body,
      onPress: () => navigateToContent(data),
    });
  });

  // User tapped notification (foreground or background)
  useNotificationResponse((response) => {
    const data = response.notification.request.content.data;
    const actionId = response.actionIdentifier;

    switch (actionId) {
      case 'reply':
        const replyText = response.userText;
        api.sendQuickReply(data.conversationId, replyText);
        break;
      case 'mark_read':
        api.markAsRead(data.conversationId);
        break;
      default:
        navigateToContent(data);
    }
  });

  return null;
}

function navigateToContent(data: any) {
  switch (data.type) {
    case 'chat_message':
      navigation.navigate('Chat', { conversationId: data.conversationId });
      break;
    case 'reminder':
      navigation.navigate('Reminders', { id: data.reminderId });
      break;
  }
}
```

### Badge Management

```tsx
import { setBadgeCount, getBadgeCount } from 'expo-push-notifications';

// Update badge when unread count changes
export function useBadgeSync() {
  const { data: unreadCount } = useQuery({
    queryKey: ['unread-count'],
    queryFn: api.getUnreadCount,
    refetchInterval: 30000,
  });

  useEffect(() => {
    if (unreadCount !== undefined) {
      setBadgeCount(unreadCount);
    }
  }, [unreadCount]);

  // Clear badge when app comes to foreground
  useAppState((state) => {
    if (state === 'active') {
      setBadgeCount(0);
    }
  });
}
```

---

## 3. Supabase Realtime

### Database Change Listeners

```tsx
import {
  useRealtimeSubscription,
  RealtimeChannel,
  RealtimeFilter,
} from 'supabase-realtime';

export function useRealtimeMessages(conversationId: string) {
  const queryClient = useQueryClient();

  useRealtimeSubscription({
    channel: `messages:${conversationId}`,
    table: 'messages',
    filter: `conversation_id=eq.${conversationId}`,
    event: '*',  // INSERT, UPDATE, DELETE
    onInsert: (newMessage) => {
      // Optimistically add to cache
      queryClient.setQueryData(
        ['messages', conversationId],
        (old: Message[]) => [...(old ?? []), newMessage],
      );
    },
    onUpdate: (updatedMessage) => {
      queryClient.setQueryData(
        ['messages', conversationId],
        (old: Message[]) =>
          (old ?? []).map((m) =>
            m.id === updatedMessage.id ? updatedMessage : m
          ),
      );
    },
    onDelete: (deletedMessage) => {
      queryClient.setQueryData(
        ['messages', conversationId],
        (old: Message[]) =>
          (old ?? []).filter((m) => m.id !== deletedMessage.id),
      );
    },
  });
}
```

### Presence Tracking

```tsx
import {
  useRealtimePresence,
  PresenceState,
} from 'supabase-realtime';

export function OnlineUsersIndicator({ channelName }: { channelName: string }) {
  const { presenceState, track, untrack } = useRealtimePresence(channelName);

  // Track current user's presence
  useEffect(() => {
    track({
      user_id: currentUser.id,
      username: currentUser.name,
      online_at: new Date().toISOString(),
      status: 'online',
    });

    return () => untrack();
  }, []);

  const onlineUsers = useMemo(() => {
    return Object.values(presenceState)
      .flat()
      .filter((p) => p.user_id !== currentUser.id);
  }, [presenceState]);

  return (
    <View style={styles.row}>
      <View style={[styles.dot, { backgroundColor: '#22c55e' }]} />
      <Text>{onlineUsers.length} online</Text>
      {onlineUsers.slice(0, 3).map((user) => (
        <Avatar key={user.user_id} name={user.username} size={24} />
      ))}
    </View>
  );
}
```

### Broadcast Channels

```tsx
import { useBroadcastChannel } from 'supabase-realtime';

export function CollaborativeEditor({ documentId }) {
  const { broadcast, onMessage } = useBroadcastChannel(`doc:${documentId}`);

  // Broadcast cursor position
  const handleCursorMove = useCallback(
    (position: { line: number; column: number }) => {
      broadcast('cursor_move', {
        userId: currentUser.id,
        position,
        color: currentUser.cursorColor,
      });
    },
    [broadcast]
  );

  // Receive other users' cursor positions
  onMessage('cursor_move', (payload) => {
    if (payload.userId !== currentUser.id) {
      updateRemoteCursor(payload.userId, payload.position, payload.color);
    }
  });

  return <Editor onCursorMove={handleCursorMove} />;
}
```

---

## 4. Omni-Channel Routing

### Channel Router Setup

```tsx
import {
  ChannelRouter,
  NotificationChannel,
  DeliveryRule,
  UserPreferences,
} from 'omni-channel-core';

const router = new ChannelRouter({
  channels: [
    NotificationChannel.PUSH,
    NotificationChannel.IN_APP,
    NotificationChannel.EMAIL,
    NotificationChannel.SMS,
  ],
  defaultRules: [
    // Try push first, fall back to email after 5 minutes
    DeliveryRule.create({
      event: 'chat_message',
      primary: NotificationChannel.PUSH,
      fallback: NotificationChannel.EMAIL,
      fallbackDelayMs: 5 * 60 * 1000,
      throttle: { maxPerHour: 20 },
    }),
    // Marketing: respect quiet hours, email only
    DeliveryRule.create({
      event: 'marketing_promo',
      primary: NotificationChannel.EMAIL,
      respectQuietHours: true,
      quietHoursStart: '22:00',
      quietHoursEnd: '08:00',
    }),
    // Critical: push + SMS immediately
    DeliveryRule.create({
      event: 'security_alert',
      channels: [NotificationChannel.PUSH, NotificationChannel.SMS],
      parallel: true,
      bypassQuietHours: true,
    }),
  ],
});
```

### Sending Multi-Channel Notifications

```tsx
import { ChannelRouter, NotificationPayload } from 'omni-channel-core';

async function notifyNewMessage(
  recipientId: string,
  message: ChatMessage,
) {
  const payload: NotificationPayload = {
    event: 'chat_message',
    recipientId,
    title: `New message from ${message.senderName}`,
    body: message.preview,
    data: {
      type: 'chat_message',
      conversationId: message.conversationId,
      messageId: message.id,
    },
    // Channel-specific overrides
    channelOverrides: {
      [NotificationChannel.PUSH]: {
        badge: await getUnreadCount(recipientId),
        sound: 'message.wav',
        categoryId: 'MESSAGE',
      },
      [NotificationChannel.EMAIL]: {
        subject: `${message.senderName} sent you a message`,
        template: 'chat-notification',
        templateData: {
          senderName: message.senderName,
          senderAvatar: message.senderAvatar,
          messagePreview: message.preview,
          actionUrl: `https://app.example.com/chat/${message.conversationId}`,
        },
      },
    },
  };

  const result = await router.send(payload);
  console.log(`Delivered via: ${result.deliveredChannels.join(', ')}`);
}
```

### User Notification Preferences

```tsx
import {
  NotificationPreferencesScreen,
  useUserPreferences,
  PreferenceCategory,
} from 'omni-channel-core';

export function NotificationSettings() {
  const { preferences, updatePreference, isLoading } = useUserPreferences();

  const categories: PreferenceCategory[] = [
    {
      id: 'messages',
      title: 'Messages',
      description: 'Chat messages and replies',
      channels: ['push', 'email', 'in_app'],
      defaults: { push: true, email: false, in_app: true },
    },
    {
      id: 'reminders',
      title: 'Reminders',
      description: 'Task and event reminders',
      channels: ['push', 'email'],
      defaults: { push: true, email: true },
    },
    {
      id: 'marketing',
      title: 'Promotions',
      description: 'Deals and feature announcements',
      channels: ['push', 'email'],
      defaults: { push: false, email: true },
    },
  ];

  return (
    <NotificationPreferencesScreen
      categories={categories}
      preferences={preferences}
      onToggle={(categoryId, channel, enabled) =>
        updatePreference(categoryId, channel, enabled)
      }
      isLoading={isLoading}
    />
  );
}
```

### Delivery Tracking

```tsx
import { DeliveryTracker, DeliveryStatus } from 'omni-channel-core';

const tracker = new DeliveryTracker();

// Track delivery status
const status = await tracker.getStatus(notificationId);
console.log(`Status: ${status.state}`);
// DeliveryStatus.SENT | DELIVERED | READ | FAILED | BOUNCED

// Get delivery analytics
const analytics = await tracker.getAnalytics({
  dateRange: { start: '2026-02-01', end: '2026-02-16' },
  groupBy: 'channel',
});

for (const channel of analytics.channels) {
  console.log(`${channel.name}: ${channel.deliveryRate}% delivered, ${channel.openRate}% opened`);
}
```

---

## 5. Integrating Chat with Push and Realtime

### Full-Stack Chat Architecture

```tsx
import { useChatMessages } from 'mobile-chat';
import { useRealtimeSubscription } from 'supabase-realtime';
import { useNotificationResponse } from 'expo-push-notifications';
import { ChannelRouter, NotificationChannel } from 'omni-channel-core';

export function useLiveChat(conversationId: string) {
  const chat = useChatMessages(conversationId);

  // Live updates via Supabase when app is in foreground
  useRealtimeSubscription({
    channel: `messages:${conversationId}`,
    table: 'messages',
    filter: `conversation_id=eq.${conversationId}`,
    event: 'INSERT',
    onInsert: (newMessage) => {
      chat.addOptimistic(newMessage);
    },
  });

  // Handle push notification taps to navigate to this chat
  useNotificationResponse((response) => {
    const data = response.notification.request.content.data;
    if (data.conversationId === conversationId) {
      chat.markAsRead(conversationId);
    }
  });

  // Send message and notify via push
  const sendWithNotification = async (content: string) => {
    const message = await chat.sendMessage({ type: 'text', content });

    // Supabase INSERT trigger will notify other participants in realtime
    // Push notification for offline participants is handled server-side
  };

  return {
    ...chat,
    sendMessage: sendWithNotification,
  };
}
```

---

## Quick Reference

| Task | Module | Key API |
|------|--------|---------|
| Render chat UI | `mobile-chat` | `<ChatContainer>`, `<MessageList>`, `<MessageInput>` |
| Send messages | `mobile-chat` | `useChatMessages().sendMessage()` |
| Show typing indicator | `mobile-chat` | `<TypingIndicator>`, `useTypingStatus()` |
| Read receipts | `mobile-chat` | `useChatMessages().markAsRead()` |
| Media messages | `mobile-chat` | `<MediaMessage>`, `<LocationMessage>` |
| Register push token | `expo-push-notifications` | `usePushNotifications().token` |
| Handle foreground notification | `expo-push-notifications` | `useNotificationReceived(callback)` |
| Handle notification tap | `expo-push-notifications` | `useNotificationResponse(callback)` |
| Manage badge count | `expo-push-notifications` | `setBadgeCount(n)` |
| Notification actions | `expo-push-notifications` | `setNotificationCategories(cats)` |
| Subscribe to DB changes | `supabase-realtime` | `useRealtimeSubscription(opts)` |
| Track user presence | `supabase-realtime` | `useRealtimePresence(channel)` |
| Broadcast events | `supabase-realtime` | `useBroadcastChannel(name)` |
| Route notifications | `omni-channel-core` | `ChannelRouter.send(payload)` |
| User preferences | `omni-channel-core` | `useUserPreferences()` |
| Track delivery | `omni-channel-core` | `DeliveryTracker.getStatus(id)` |

### Architecture Decision Tree

```
What communication feature do you need?
├── In-app chat → mobile-chat
│   ├── Basic text chat → ChatContainer + MessageList + MessageInput
│   ├── Media messages → MediaMessage + LocationMessage
│   └── Typing/read receipts → TypingIndicator + markAsRead
├── Background notifications → expo-push-notifications
│   ├── Token registration → usePushNotifications
│   ├── Foreground handling → useNotificationReceived
│   ├── Tap handling → useNotificationResponse
│   └── Action buttons → setNotificationCategories
├── Live updates (foreground) → supabase-realtime
│   ├── DB change listeners → useRealtimeSubscription
│   ├── Online status → useRealtimePresence
│   └── Custom events → useBroadcastChannel
└── Multi-channel routing → omni-channel-core
    ├── Route to best channel → ChannelRouter + DeliveryRule
    ├── User preferences → NotificationPreferencesScreen
    └── Delivery analytics → DeliveryTracker
```

---

# Research Update: February 2026

| Technology | Version | Key Change |
|-----------|---------|------------|
| Expo SDK | 54.0.33 | Deprecated `expo-notifications` functions removed. Update notification handler imports. |
| React Native | 0.84.0 | New Architecture only. Hermes V1 default. All push notification libraries must support Fabric/TurboModules. |
| Supabase | 2.95.3 | New key model: `sb_publishable_` (anon), `sb_secret_` (service_role). "Sign in With Your App" for MCP servers. Edge Functions support legacy Node.js. |

**Action items for this skill:**
- Update Supabase client initialization to use new API key format when available
- Verify expo-push-notifications module works with Expo SDK 54 (deprecated functions removed)
- Ensure all realtime subscriptions use New Architecture-compatible libraries
