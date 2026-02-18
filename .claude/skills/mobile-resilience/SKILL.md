---
name: mobile-resilience
description: "Mobile app resilience patterns — offline support, crash reporting, permission flows, and forced update mechanisms. Use when: (1) Building offline-first features, (2) Setting up crash reporting, (3) Implementing permission request flows, (4) Adding forced app update gates."
consumes_modules:
  - mobile-network-status
  - mobile-crash-reporting
  - mobile-permissions
  - mobile-app-update
---

# Mobile Resilience

> Mobile app resilience patterns — offline support, crash reporting, permission flows, and forced update mechanisms. Use when: handling offline/online transitions, setting up Sentry crash reporting, building permission request UX, or gating users on minimum app versions.

---

## Module Dependencies

| Module | What It Provides |
|--------|-----------------|
| `mobile-network-status` | Network connectivity detection, offline queue, sync manager, connection quality monitoring |
| `mobile-crash-reporting` | Sentry integration, error boundaries, breadcrumb tracking, performance monitoring, user feedback |
| `mobile-permissions` | Permission request flows, pre-prompt dialogs, permission status tracking, settings deep links |
| `mobile-app-update` | Version checking, forced update gate, soft update prompts, app store links, changelog display |

---

## Overview

This skill covers the defensive patterns that make mobile apps reliable in the real world. Users lose connectivity, apps crash, permissions get denied, and app versions go stale. These 4 modules handle each failure mode:

- **Connectivity**: `mobile-network-status` detects offline state and queues actions for later sync
- **Stability**: `mobile-crash-reporting` captures crashes and errors for debugging
- **Access**: `mobile-permissions` guides users through granting necessary permissions
- **Currency**: `mobile-app-update` ensures users run supported app versions

All examples use React Native with Expo SDK and TypeScript.

---

## 1. Network Status and Offline Support

### Network Status Provider

```tsx
import {
  NetworkStatusProvider,
  useNetworkStatus,
  NetworkBanner,
  ConnectionQuality,
} from 'mobile-network-status';

export function App() {
  return (
    <NetworkStatusProvider
      pingUrl="https://api.example.com/health"
      pingIntervalMs={30000}
      onStatusChange={(status) => {
        console.log(`Network: ${status.isConnected ? 'online' : 'offline'}`);
        console.log(`Quality: ${status.quality}`);
      }}
    >
      <NetworkBanner
        offlineMessage="You are offline. Changes will sync when you reconnect."
        slowMessage="Slow connection detected."
        position="top"
      />
      <AppNavigator />
    </NetworkStatusProvider>
  );
}
```

### Offline Action Queue

```tsx
import {
  useOfflineQueue,
  QueuedAction,
  SyncManager,
} from 'mobile-network-status';

export function useOfflineCreatePost() {
  const { enqueue, pendingCount } = useOfflineQueue();
  const { isConnected } = useNetworkStatus();

  const createPost = async (post: PostDraft) => {
    if (isConnected) {
      // Online: send immediately
      return await api.createPost(post);
    }

    // Offline: queue for later
    const action: QueuedAction = {
      id: uuid(),
      type: 'CREATE_POST',
      payload: post,
      createdAt: new Date().toISOString(),
      retryCount: 0,
      maxRetries: 3,
    };

    await enqueue(action);
    return { ...post, id: action.id, pending: true };
  };

  return { createPost, pendingCount };
}
```

### Sync Manager

```tsx
import { SyncManager, SyncStrategy, ConflictResolver } from 'mobile-network-status';

const syncManager = new SyncManager({
  strategy: SyncStrategy.QUEUE_AND_RETRY,
  maxRetries: 5,
  retryBackoff: 'exponential',   // 1s, 2s, 4s, 8s, 16s
  batchSize: 10,
  conflictResolver: ConflictResolver.LAST_WRITE_WINS,
  onSyncStart: () => console.log('Sync started'),
  onSyncComplete: (results) => {
    console.log(`Synced: ${results.succeeded}/${results.total}`);
    if (results.failed > 0) {
      console.log(`Failed: ${results.failures.map((f) => f.error)}`);
    }
  },
});

// Register action handlers
syncManager.registerHandler('CREATE_POST', async (action) => {
  return await api.createPost(action.payload);
});

syncManager.registerHandler('UPDATE_PROFILE', async (action) => {
  return await api.updateProfile(action.payload);
});

// Start sync when network comes back
export function useSyncOnReconnect() {
  const { isConnected } = useNetworkStatus();
  const prevConnected = useRef(isConnected);

  useEffect(() => {
    if (isConnected && !prevConnected.current) {
      // Just came back online
      syncManager.syncAll();
    }
    prevConnected.current = isConnected;
  }, [isConnected]);
}
```

### Optimistic UI with Offline Support

```tsx
import { useNetworkStatus, useOfflineQueue } from 'mobile-network-status';

export function useLikePost() {
  const queryClient = useQueryClient();
  const { isConnected } = useNetworkStatus();
  const { enqueue } = useOfflineQueue();

  return useMutation({
    mutationFn: async (postId: string) => {
      if (isConnected) {
        return api.likePost(postId);
      }
      await enqueue({
        id: uuid(),
        type: 'LIKE_POST',
        payload: { postId },
        createdAt: new Date().toISOString(),
      });
      return { postId, pending: true };
    },
    onMutate: async (postId) => {
      // Optimistic update regardless of network state
      await queryClient.cancelQueries({ queryKey: ['post', postId] });
      const prev = queryClient.getQueryData(['post', postId]);
      queryClient.setQueryData(['post', postId], (old: Post) => ({
        ...old,
        isLiked: true,
        likeCount: old.likeCount + 1,
      }));
      return { prev };
    },
    onError: (err, postId, context) => {
      queryClient.setQueryData(['post', postId], context.prev);
    },
  });
}
```

---

## 2. Crash Reporting

### Sentry Setup

```tsx
import {
  initCrashReporting,
  CrashReportingProvider,
  ErrorBoundary,
  addBreadcrumb,
  captureException,
  setUser,
} from 'mobile-crash-reporting';

// Initialize in app entry point
initCrashReporting({
  dsn: 'https://examplekey@sentry.io/123456',
  environment: __DEV__ ? 'development' : 'production',
  release: `com.example.app@${appVersion}+${buildNumber}`,
  tracesSampleRate: 0.2,           // 20% of transactions for performance
  enableAutoSessionTracking: true,
  attachStacktrace: true,
  beforeSend: (event) => {
    // Scrub sensitive data
    if (event.request?.headers) {
      delete event.request.headers['Authorization'];
    }
    return event;
  },
});

export function App() {
  return (
    <CrashReportingProvider>
      <ErrorBoundary
        fallback={({ error, resetError }) => (
          <CrashFallbackScreen
            error={error}
            onRetry={resetError}
            onReport={() => submitUserFeedback(error)}
          />
        )}
        onError={(error, componentStack) => {
          captureException(error, {
            extra: { componentStack },
            tags: { boundary: 'root' },
          });
        }}
      >
        <AppNavigator />
      </ErrorBoundary>
    </CrashReportingProvider>
  );
}
```

### Breadcrumb Tracking

```tsx
import { addBreadcrumb, BreadcrumbCategory } from 'mobile-crash-reporting';

// Track navigation
export function useNavigationBreadcrumbs(navigation) {
  useEffect(() => {
    const unsubscribe = navigation.addListener('state', (e) => {
      const currentRoute = getActiveRouteName(e.data.state);
      addBreadcrumb({
        category: BreadcrumbCategory.NAVIGATION,
        message: `Navigate to ${currentRoute}`,
        data: { route: currentRoute },
        level: 'info',
      });
    });
    return unsubscribe;
  }, [navigation]);
}

// Track API calls
export function apiWithBreadcrumbs(url: string, options: RequestInit) {
  addBreadcrumb({
    category: BreadcrumbCategory.HTTP,
    message: `${options.method || 'GET'} ${url}`,
    data: { url, method: options.method },
    level: 'info',
  });

  return fetch(url, options).then((response) => {
    addBreadcrumb({
      category: BreadcrumbCategory.HTTP,
      message: `${response.status} ${url}`,
      data: { url, status: response.status },
      level: response.ok ? 'info' : 'warning',
    });
    return response;
  });
}

// Track user actions
export function trackUserAction(action: string, data?: Record<string, any>) {
  addBreadcrumb({
    category: BreadcrumbCategory.USER,
    message: action,
    data,
    level: 'info',
  });
}
```

### Screen-Level Error Boundaries

```tsx
import { ErrorBoundary, captureException } from 'mobile-crash-reporting';

export function withErrorBoundary(
  WrappedComponent: React.ComponentType,
  screenName: string,
) {
  return function ProtectedScreen(props: any) {
    return (
      <ErrorBoundary
        fallback={({ error, resetError }) => (
          <ScreenErrorFallback
            screenName={screenName}
            error={error}
            onRetry={resetError}
          />
        )}
        onError={(error) => {
          captureException(error, {
            tags: { screen: screenName },
          });
        }}
      >
        <WrappedComponent {...props} />
      </ErrorBoundary>
    );
  };
}

// Usage
const ProtectedProfile = withErrorBoundary(ProfileScreen, 'Profile');
const ProtectedFeed = withErrorBoundary(FeedScreen, 'Feed');
```

### User Feedback on Crash

```tsx
import { showUserFeedbackDialog, captureUserFeedback } from 'mobile-crash-reporting';

function CrashFallbackScreen({ error, onRetry }) {
  const handleReport = async () => {
    const feedback = await showUserFeedbackDialog({
      title: 'Something went wrong',
      subtitle: 'Help us fix this by telling us what happened',
      namePlaceholder: 'Your name',
      emailPlaceholder: 'Your email',
      commentsPlaceholder: 'What were you doing when this happened?',
    });

    if (feedback) {
      await captureUserFeedback({
        eventId: error.sentryEventId,
        name: feedback.name,
        email: feedback.email,
        comments: feedback.comments,
      });
    }
  };

  return (
    <View style={styles.center}>
      <Text style={styles.title}>Oops!</Text>
      <Text style={styles.body}>Something went wrong. Please try again.</Text>
      <Button title="Try Again" onPress={onRetry} />
      <Button title="Report Issue" onPress={handleReport} variant="outline" />
    </View>
  );
}
```

---

## 3. Permission Flows

### Permission Request with Pre-Prompt

```tsx
import {
  usePermission,
  PermissionType,
  PrePromptDialog,
  openAppSettings,
} from 'mobile-permissions';

export function CameraFeature() {
  const {
    status,
    request,
    isGranted,
    isPermanentlyDenied,
  } = usePermission(PermissionType.CAMERA);

  const [showPrePrompt, setShowPrePrompt] = useState(false);

  const handleCameraPress = async () => {
    if (isGranted) {
      openCamera();
      return;
    }

    if (isPermanentlyDenied) {
      // User previously denied and checked "Don't ask again"
      Alert.alert(
        'Camera Access Required',
        'Please enable camera access in Settings to use this feature.',
        [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Open Settings', onPress: openAppSettings },
        ],
      );
      return;
    }

    // Show pre-prompt before system dialog
    setShowPrePrompt(true);
  };

  return (
    <>
      <Button title="Take Photo" onPress={handleCameraPress} />

      <PrePromptDialog
        visible={showPrePrompt}
        icon="camera"
        title="Camera Access"
        description="We need camera access to let you take photos for your profile and posts."
        allowLabel="Continue"
        denyLabel="Not Now"
        onAllow={async () => {
          setShowPrePrompt(false);
          const result = await request();
          if (result === 'granted') {
            openCamera();
          }
        }}
        onDeny={() => setShowPrePrompt(false)}
      />
    </>
  );
}
```

### Multi-Permission Onboarding

```tsx
import {
  PermissionOnboarding,
  PermissionStep,
  useMultiplePermissions,
  PermissionType,
} from 'mobile-permissions';

const REQUIRED_PERMISSIONS: PermissionStep[] = [
  {
    type: PermissionType.NOTIFICATIONS,
    title: 'Stay Updated',
    description: 'Get notified about messages, reminders, and important updates.',
    icon: 'bell',
    required: false,  // soft ask
  },
  {
    type: PermissionType.LOCATION,
    title: 'Find Nearby',
    description: 'Discover places and people near you.',
    icon: 'map-pin',
    required: false,
  },
  {
    type: PermissionType.CAMERA,
    title: 'Share Moments',
    description: 'Take photos and videos to share with friends.',
    icon: 'camera',
    required: false,
  },
];

export function PermissionSetupScreen({ navigation }) {
  const { statuses, requestAll } = useMultiplePermissions(
    REQUIRED_PERMISSIONS.map((p) => p.type),
  );

  return (
    <PermissionOnboarding
      steps={REQUIRED_PERMISSIONS}
      statuses={statuses}
      onRequestPermission={async (type) => {
        const result = await requestAll([type]);
        return result[type];
      }}
      onComplete={() => navigation.replace('Home')}
      onSkip={() => navigation.replace('Home')}
      showSkipButton
    />
  );
}
```

### Permission Status Dashboard

```tsx
import {
  usePermission,
  PermissionType,
  PermissionStatusBadge,
  openAppSettings,
} from 'mobile-permissions';

export function PermissionSettingsScreen() {
  const camera = usePermission(PermissionType.CAMERA);
  const location = usePermission(PermissionType.LOCATION);
  const notifications = usePermission(PermissionType.NOTIFICATIONS);
  const contacts = usePermission(PermissionType.CONTACTS);

  const permissions = [
    { label: 'Camera', perm: camera, icon: 'camera' },
    { label: 'Location', perm: location, icon: 'map-pin' },
    { label: 'Notifications', perm: notifications, icon: 'bell' },
    { label: 'Contacts', perm: contacts, icon: 'users' },
  ];

  return (
    <ScrollView>
      <Text style={styles.header}>App Permissions</Text>
      {permissions.map(({ label, perm, icon }) => (
        <View key={label} style={styles.row}>
          <Icon name={icon} />
          <Text>{label}</Text>
          <PermissionStatusBadge status={perm.status} />
          {perm.isPermanentlyDenied && (
            <Button title="Settings" onPress={openAppSettings} size="small" />
          )}
        </View>
      ))}
    </ScrollView>
  );
}
```

---

## 4. App Update Gate

### Version Check and Update Prompt

```tsx
import {
  AppUpdateProvider,
  useAppUpdate,
  UpdateGate,
  UpdatePrompt,
  UpdateSeverity,
} from 'mobile-app-update';

export function App() {
  return (
    <AppUpdateProvider
      checkUrl="https://api.example.com/app/version"
      checkIntervalMs={3600000}   // check every hour
      currentVersion="2.3.1"
      currentBuildNumber={142}
    >
      <UpdateGate
        renderForceUpdate={(updateInfo) => (
          <ForceUpdateScreen
            currentVersion={updateInfo.currentVersion}
            requiredVersion={updateInfo.minimumVersion}
            changelog={updateInfo.changelog}
            storeUrl={updateInfo.storeUrl}
          />
        )}
      >
        <AppNavigator />
      </UpdateGate>
    </AppUpdateProvider>
  );
}
```

### Force Update Screen

```tsx
import {
  useAppUpdate,
  openStore,
  ChangelogDisplay,
} from 'mobile-app-update';

function ForceUpdateScreen({ currentVersion, requiredVersion, changelog, storeUrl }) {
  return (
    <View style={styles.center}>
      <Image source={require('../assets/update-icon.png')} />
      <Text style={styles.title}>Update Required</Text>
      <Text style={styles.body}>
        You are running v{currentVersion}. Please update to v{requiredVersion}
        or later to continue using the app.
      </Text>

      <ChangelogDisplay
        entries={changelog}
        maxEntries={5}
      />

      <Button
        title="Update Now"
        onPress={() => openStore(storeUrl)}
        style={styles.primaryButton}
      />
    </View>
  );
}
```

### Soft Update Prompt

```tsx
import {
  useAppUpdate,
  UpdatePrompt,
  UpdateSeverity,
} from 'mobile-app-update';

export function SoftUpdateBanner() {
  const { updateAvailable, updateInfo, dismiss } = useAppUpdate();

  if (!updateAvailable || updateInfo.severity === UpdateSeverity.FORCE) {
    return null;  // Force updates handled by UpdateGate
  }

  return (
    <UpdatePrompt
      severity={updateInfo.severity}
      version={updateInfo.latestVersion}
      changelog={updateInfo.changelog}
      onUpdate={() => openStore(updateInfo.storeUrl)}
      onDismiss={dismiss}
      dismissable={updateInfo.severity !== UpdateSeverity.RECOMMENDED}
      reminderIntervalMs={
        updateInfo.severity === UpdateSeverity.RECOMMENDED
          ? 24 * 60 * 60 * 1000    // remind daily for recommended
          : 7 * 24 * 60 * 60 * 1000 // remind weekly for optional
      }
    />
  );
}
```

### Version Check API Response Format

```tsx
// Expected server response from checkUrl
interface VersionCheckResponse {
  latestVersion: string;       // "2.5.0"
  minimumVersion: string;      // "2.0.0" — anything below this is force update
  recommendedVersion: string;  // "2.4.0" — anything below this gets soft prompt
  storeUrl: {
    ios: string;               // App Store URL
    android: string;           // Play Store URL
  };
  changelog: Array<{
    version: string;
    date: string;
    changes: string[];
  }>;
  maintenanceMode?: {
    enabled: boolean;
    message: string;
    estimatedEndTime: string;
  };
}

// Version comparison logic
import { compareVersions } from 'mobile-app-update';

function getUpdateSeverity(
  current: string,
  check: VersionCheckResponse,
): UpdateSeverity {
  if (compareVersions(current, check.minimumVersion) < 0) {
    return UpdateSeverity.FORCE;
  }
  if (compareVersions(current, check.recommendedVersion) < 0) {
    return UpdateSeverity.RECOMMENDED;
  }
  if (compareVersions(current, check.latestVersion) < 0) {
    return UpdateSeverity.OPTIONAL;
  }
  return UpdateSeverity.NONE;
}
```

---

## 5. Combining Resilience Patterns

### Resilience Provider Stack

```tsx
import { NetworkStatusProvider } from 'mobile-network-status';
import { CrashReportingProvider, ErrorBoundary } from 'mobile-crash-reporting';
import { AppUpdateProvider, UpdateGate } from 'mobile-app-update';

export function ResilienceProviders({ children }) {
  return (
    <CrashReportingProvider>
      <ErrorBoundary fallback={CrashFallbackScreen}>
        <AppUpdateProvider
          checkUrl="https://api.example.com/app/version"
          currentVersion={APP_VERSION}
        >
          <UpdateGate renderForceUpdate={ForceUpdateScreen}>
            <NetworkStatusProvider pingUrl="https://api.example.com/health">
              {children}
            </NetworkStatusProvider>
          </UpdateGate>
        </AppUpdateProvider>
      </ErrorBoundary>
    </CrashReportingProvider>
  );
}

// Usage in App.tsx
export function App() {
  return (
    <ResilienceProviders>
      <AppNavigator />
    </ResilienceProviders>
  );
}
```

---

## Quick Reference

| Task | Module | Key API |
|------|--------|---------|
| Detect online/offline | `mobile-network-status` | `useNetworkStatus().isConnected` |
| Show offline banner | `mobile-network-status` | `<NetworkBanner>` |
| Queue offline actions | `mobile-network-status` | `useOfflineQueue().enqueue(action)` |
| Sync on reconnect | `mobile-network-status` | `SyncManager.syncAll()` |
| Conflict resolution | `mobile-network-status` | `ConflictResolver.LAST_WRITE_WINS` |
| Init Sentry | `mobile-crash-reporting` | `initCrashReporting(config)` |
| Error boundary | `mobile-crash-reporting` | `<ErrorBoundary fallback>` |
| Track breadcrumbs | `mobile-crash-reporting` | `addBreadcrumb(crumb)` |
| Capture errors | `mobile-crash-reporting` | `captureException(error)` |
| User crash feedback | `mobile-crash-reporting` | `captureUserFeedback(feedback)` |
| Check permission | `mobile-permissions` | `usePermission(type).status` |
| Request permission | `mobile-permissions` | `usePermission(type).request()` |
| Pre-prompt dialog | `mobile-permissions` | `<PrePromptDialog>` |
| Open app settings | `mobile-permissions` | `openAppSettings()` |
| Permission onboarding | `mobile-permissions` | `<PermissionOnboarding steps>` |
| Check for updates | `mobile-app-update` | `useAppUpdate().updateAvailable` |
| Force update gate | `mobile-app-update` | `<UpdateGate renderForceUpdate>` |
| Soft update prompt | `mobile-app-update` | `<UpdatePrompt severity>` |
| Open app store | `mobile-app-update` | `openStore(url)` |

### Resilience Decision Tree

```
What failure mode are you handling?
├── No internet connection → mobile-network-status
│   ├── Show status banner → NetworkBanner
│   ├── Queue writes → useOfflineQueue
│   ├── Sync when back online → SyncManager
│   └── Handle conflicts → ConflictResolver
├── App crashes → mobile-crash-reporting
│   ├── Global crash handler → CrashReportingProvider
│   ├── Screen-level recovery → ErrorBoundary per screen
│   ├── Debug trail → addBreadcrumb
│   └── User reports → captureUserFeedback
├── Missing permissions → mobile-permissions
│   ├── First-time ask → PrePromptDialog + request()
│   ├── Previously denied → openAppSettings()
│   ├── Batch setup → PermissionOnboarding
│   └── Status overview → PermissionStatusBadge
└── Outdated app version → mobile-app-update
    ├── Below minimum → UpdateGate (force)
    ├── Below recommended → UpdatePrompt (soft)
    └── Below latest → UpdatePrompt (optional)
```

---

# Research Update: February 2026

| Technology | Version | Key Change |
|-----------|---------|------------|
| Expo SDK | 54.0.33 | Xcode 16.1+ required (26 recommended). Metro 0.83 internal imports changed. |
| React Native | 0.84.0 | `RCT_REMOVE_LEGACY_ARCH` is now default. No legacy bridge code in iOS builds. Reduced app size. |
| Supabase | 2.95.3 | Security notification email templates expanded (password, email, phone changes, identity linking, MFA). |

**Action items for this skill:**
- Crash reporting SDKs (Sentry) must support New Architecture natively
- Network status detection libraries must work without bridge
- Permission request flows unchanged but verify Xcode 16.1+ compatibility
- Update any `RCT_` prefixed native module references (legacy removed)
