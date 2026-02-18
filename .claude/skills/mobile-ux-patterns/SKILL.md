---
name: mobile-ux-patterns
description: "Production UX patterns for React Native/Expo mobile apps — loading states, onboarding flows, feature flags, sharing, and maps. Use when: (1) Building skeleton loading screens, (2) Creating onboarding carousels, (3) Implementing A/B testing with remote config, (4) Adding share sheets, (5) Integrating maps and location services."
consumes_modules:
  - mobile-skeleton-loaders
  - mobile-onboarding
  - mobile-remote-config
  - mobile-social-sharing
  - mobile-maps-location
---

# Mobile UX Patterns

> Production UX patterns for React Native/Expo mobile apps — loading states, onboarding flows, feature flags, sharing, and maps. Use when: building skeleton screens, onboarding carousels, remote config toggles, native share sheets, or map/location features.

---

## Module Dependencies

| Module | What It Provides |
|--------|-----------------|
| `mobile-skeleton-loaders` | Shimmer effects, skeleton screen components, content placeholder animations |
| `mobile-onboarding` | Onboarding carousel, step indicators, skip/complete logic, first-launch detection |
| `mobile-remote-config` | Feature flags, A/B test variants, remote configuration fetching, rollout rules |
| `mobile-social-sharing` | Native share sheets, deep link generation, OG metadata, platform-specific sharing |
| `mobile-maps-location` | Map rendering, geocoding, geofencing, location tracking, marker clustering |

---

## Overview

This skill consolidates 5 mobile UX modules into a unified reference for building polished React Native/Expo experiences. These patterns cover the critical moments of a mobile user journey: first launch (onboarding), content loading (skeletons), feature discovery (remote config), social engagement (sharing), and spatial context (maps).

All examples use React Native with Expo SDK and TypeScript.

---

## 1. Skeleton Loading Screens

Skeleton loaders replace blank screens during data fetching, giving users a sense of structure before content arrives.

### Basic Skeleton Component

```tsx
import {
  SkeletonContainer,
  SkeletonRect,
  SkeletonCircle,
  ShimmerOverlay,
} from 'mobile-skeleton-loaders';

interface FeedCardSkeletonProps {
  count?: number;
}

export function FeedCardSkeleton({ count = 3 }: FeedCardSkeletonProps) {
  return (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonContainer key={i} style={styles.card}>
          <ShimmerOverlay duration={1200} baseColor="#e0e0e0" highlightColor="#f5f5f5">
            {/* Avatar */}
            <SkeletonCircle size={48} />

            {/* Header lines */}
            <SkeletonRect width="60%" height={14} marginTop={8} />
            <SkeletonRect width="40%" height={12} marginTop={4} />

            {/* Body content */}
            <SkeletonRect width="100%" height={180} marginTop={12} borderRadius={8} />

            {/* Action bar */}
            <View style={styles.actionRow}>
              <SkeletonRect width={60} height={24} borderRadius={12} />
              <SkeletonRect width={60} height={24} borderRadius={12} />
              <SkeletonRect width={60} height={24} borderRadius={12} />
            </View>
          </ShimmerOverlay>
        </SkeletonContainer>
      ))}
    </>
  );
}
```

### Transition from Skeleton to Content

```tsx
import { SkeletonTransition } from 'mobile-skeleton-loaders';
import { useQuery } from '@tanstack/react-query';

export function FeedScreen() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['feed'],
    queryFn: fetchFeed,
  });

  return (
    <SkeletonTransition
      isLoading={isLoading}
      skeleton={<FeedCardSkeleton count={5} />}
      fadeInDuration={300}
    >
      <FlatList
        data={data}
        renderItem={({ item }) => <FeedCard item={item} />}
        keyExtractor={(item) => item.id}
      />
    </SkeletonTransition>
  );
}
```

### Skeleton Pattern Decision Table

| Content Type | Skeleton Shape | Animation |
|-------------|---------------|-----------|
| Avatar / Profile photo | `SkeletonCircle` | Shimmer |
| Text line | `SkeletonRect` (thin) | Shimmer |
| Image / Card | `SkeletonRect` (tall) | Pulse or Shimmer |
| List item | Combined row layout | Shimmer |
| Full page | Screen-level layout | Shimmer |

---

## 2. Onboarding Flows

### Carousel Onboarding

```tsx
import {
  OnboardingCarousel,
  OnboardingSlide,
  StepIndicator,
  useOnboardingComplete,
} from 'mobile-onboarding';

const SLIDES = [
  {
    id: 'welcome',
    title: 'Welcome to AppName',
    description: 'Your personal productivity companion',
    image: require('../assets/onboarding-1.png'),
  },
  {
    id: 'features',
    title: 'Smart Organization',
    description: 'AI-powered task sorting and prioritization',
    image: require('../assets/onboarding-2.png'),
  },
  {
    id: 'start',
    title: 'Get Started',
    description: 'Create your first project in seconds',
    image: require('../assets/onboarding-3.png'),
    cta: 'Create Project',
  },
];

export function OnboardingScreen({ navigation }) {
  const { markComplete, hasCompleted } = useOnboardingComplete('v1');

  // Skip if already completed
  if (hasCompleted) {
    navigation.replace('Home');
    return null;
  }

  return (
    <OnboardingCarousel
      slides={SLIDES}
      onSkip={() => {
        markComplete();
        navigation.replace('Home');
      }}
      onComplete={() => {
        markComplete();
        navigation.replace('Home');
      }}
      renderSlide={(slide, index) => (
        <OnboardingSlide
          key={slide.id}
          title={slide.title}
          description={slide.description}
          image={slide.image}
          ctaLabel={slide.cta}
        />
      )}
      renderIndicator={(current, total) => (
        <StepIndicator
          currentStep={current}
          totalSteps={total}
          activeColor="#4F46E5"
          inactiveColor="#D1D5DB"
        />
      )}
      showSkipButton={true}
      skipLabel="Skip"
    />
  );
}
```

### Conditional Onboarding with Feature Flags

```tsx
import { useOnboardingComplete } from 'mobile-onboarding';
import { useRemoteConfig } from 'mobile-remote-config';

export function AppNavigator() {
  const { hasCompleted } = useOnboardingComplete('v2');
  const { getValue } = useRemoteConfig();
  const showOnboarding = getValue('show_onboarding_v2', true);

  const initialRoute = !hasCompleted && showOnboarding ? 'Onboarding' : 'Home';

  return (
    <NavigationContainer>
      <Stack.Navigator initialRouteName={initialRoute}>
        <Stack.Screen name="Onboarding" component={OnboardingScreen} />
        <Stack.Screen name="Home" component={HomeScreen} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
```

---

## 3. Remote Config and Feature Flags

### Setup and Initialization

```tsx
import {
  RemoteConfigProvider,
  useRemoteConfig,
  useFeatureFlag,
  RemoteConfigDefaults,
} from 'mobile-remote-config';

const DEFAULTS: RemoteConfigDefaults = {
  new_checkout_flow: false,
  max_upload_size_mb: 10,
  onboarding_variant: 'carousel',
  promo_banner_text: '',
  enable_dark_mode: true,
};

export function App() {
  return (
    <RemoteConfigProvider
      defaults={DEFAULTS}
      fetchIntervalMs={3600000}  // 1 hour
      onFetchComplete={(config) => console.log('Config loaded:', config)}
    >
      <AppNavigator />
    </RemoteConfigProvider>
  );
}
```

### A/B Testing with Variants

```tsx
import { useFeatureFlag, useExperimentVariant } from 'mobile-remote-config';

export function CheckoutScreen() {
  const useNewFlow = useFeatureFlag('new_checkout_flow');
  const variant = useExperimentVariant('checkout_experiment');

  // Track exposure for analytics
  useEffect(() => {
    analytics.track('experiment_exposure', {
      experiment: 'checkout_experiment',
      variant: variant,
    });
  }, [variant]);

  if (useNewFlow && variant === 'streamlined') {
    return <StreamlinedCheckout />;
  }

  if (useNewFlow && variant === 'one_page') {
    return <OnePageCheckout />;
  }

  return <ClassicCheckout />;
}
```

### Staged Rollout Pattern

```tsx
import { useRolloutPercentage } from 'mobile-remote-config';

export function FeatureGatedComponent({ children }) {
  const isEnabled = useRolloutPercentage('premium_search', {
    percentage: 25,         // 25% of users
    stickyByUserId: true,   // same user always gets same result
  });

  if (!isEnabled) return null;

  return children;
}
```

---

## 4. Social Sharing

### Native Share Sheet

```tsx
import {
  ShareSheet,
  useShareContent,
  generateDeepLink,
  buildOGMetadata,
} from 'mobile-social-sharing';

export function ArticleScreen({ article }) {
  const { share, isSharing } = useShareContent();

  const handleShare = async () => {
    const deepLink = await generateDeepLink({
      path: `/articles/${article.id}`,
      params: { utm_source: 'share', utm_medium: 'mobile' },
      fallbackUrl: `https://app.example.com/articles/${article.id}`,
    });

    await share({
      title: article.title,
      message: article.summary,
      url: deepLink,
      type: 'article',
    });
  };

  return (
    <ScrollView>
      <ArticleContent article={article} />
      <ShareButton onPress={handleShare} loading={isSharing} />
    </ScrollView>
  );
}
```

### Platform-Specific Sharing

```tsx
import {
  shareTo,
  SharePlatform,
  canShareTo,
} from 'mobile-social-sharing';

export function ShareOptions({ content }) {
  const platforms = [
    { platform: SharePlatform.TWITTER, label: 'Twitter' },
    { platform: SharePlatform.WHATSAPP, label: 'WhatsApp' },
    { platform: SharePlatform.INSTAGRAM_STORIES, label: 'Instagram' },
    { platform: SharePlatform.COPY_LINK, label: 'Copy Link' },
  ];

  return (
    <View style={styles.shareRow}>
      {platforms.map(({ platform, label }) => (
        <ShareIcon
          key={platform}
          label={label}
          disabled={!canShareTo(platform)}
          onPress={() => shareTo(platform, {
            text: content.message,
            url: content.url,
            imageUrl: content.imageUrl,
          })}
        />
      ))}
    </View>
  );
}
```

---

## 5. Maps and Location

### Map with Marker Clustering

```tsx
import {
  MapView,
  MarkerCluster,
  UserLocationMarker,
  useCurrentLocation,
} from 'mobile-maps-location';

export function NearbyScreen() {
  const { location, error, requestPermission } = useCurrentLocation({
    accuracy: 'balanced',
    distanceFilter: 50,  // update every 50m
  });

  const { data: places } = useQuery({
    queryKey: ['nearby', location?.latitude, location?.longitude],
    queryFn: () => fetchNearbyPlaces(location),
    enabled: !!location,
  });

  if (error) {
    return <LocationPermissionPrompt onRequest={requestPermission} />;
  }

  return (
    <MapView
      initialRegion={{
        latitude: location?.latitude ?? 37.7749,
        longitude: location?.longitude ?? -122.4194,
        latitudeDelta: 0.05,
        longitudeDelta: 0.05,
      }}
      showsUserLocation
    >
      <MarkerCluster
        data={places ?? []}
        clusterRadius={50}
        renderCluster={(cluster) => (
          <ClusterMarker count={cluster.count} coordinate={cluster.coordinate} />
        )}
        renderMarker={(place) => (
          <PlaceMarker
            key={place.id}
            coordinate={place.coordinate}
            title={place.name}
            onPress={() => navigation.navigate('PlaceDetail', { id: place.id })}
          />
        )}
      />
    </MapView>
  );
}
```

### Geocoding and Search

```tsx
import { geocode, reverseGeocode, useLocationSearch } from 'mobile-maps-location';

export function LocationPicker({ onSelect }) {
  const { query, setQuery, results, isSearching } = useLocationSearch({
    debounceMs: 300,
    resultLimit: 5,
    biasToCurrentLocation: true,
  });

  const handleSelect = async (result) => {
    const details = await geocode(result.address);
    onSelect({
      address: result.address,
      latitude: details.latitude,
      longitude: details.longitude,
      placeId: details.placeId,
    });
  };

  return (
    <View>
      <TextInput
        value={query}
        onChangeText={setQuery}
        placeholder="Search for a location..."
      />
      {isSearching && <ActivityIndicator />}
      <FlatList
        data={results}
        renderItem={({ item }) => (
          <LocationRow item={item} onPress={() => handleSelect(item)} />
        )}
        keyExtractor={(item) => item.placeId}
      />
    </View>
  );
}
```

### Geofencing

```tsx
import { GeofenceManager, GeofenceEvent } from 'mobile-maps-location';

const geofence = new GeofenceManager();

// Register geofence regions
await geofence.register([
  {
    id: 'office',
    latitude: 37.7749,
    longitude: -122.4194,
    radius: 200,  // meters
    notifyOnEntry: true,
    notifyOnExit: true,
  },
]);

// Listen for events
geofence.onEvent((event: GeofenceEvent) => {
  if (event.type === 'enter') {
    console.log(`Entered region: ${event.regionId}`);
  } else if (event.type === 'exit') {
    console.log(`Exited region: ${event.regionId}`);
  }
});
```

---

## Quick Reference

| Task | Module | Key API |
|------|--------|---------|
| Show loading placeholder | `mobile-skeleton-loaders` | `<SkeletonContainer>`, `<ShimmerOverlay>` |
| Circular skeleton | `mobile-skeleton-loaders` | `<SkeletonCircle size={n}>` |
| Rectangular skeleton | `mobile-skeleton-loaders` | `<SkeletonRect width height>` |
| Animate skeleton-to-content | `mobile-skeleton-loaders` | `<SkeletonTransition isLoading>` |
| Show onboarding carousel | `mobile-onboarding` | `<OnboardingCarousel slides>` |
| Track onboarding completion | `mobile-onboarding` | `useOnboardingComplete(version)` |
| Read feature flag | `mobile-remote-config` | `useFeatureFlag(key)` |
| A/B test variant | `mobile-remote-config` | `useExperimentVariant(key)` |
| Staged rollout | `mobile-remote-config` | `useRolloutPercentage(key, opts)` |
| Open native share sheet | `mobile-social-sharing` | `useShareContent().share(content)` |
| Generate deep link | `mobile-social-sharing` | `generateDeepLink(opts)` |
| Share to specific platform | `mobile-social-sharing` | `shareTo(platform, content)` |
| Render map | `mobile-maps-location` | `<MapView initialRegion>` |
| Cluster markers | `mobile-maps-location` | `<MarkerCluster data>` |
| Get user location | `mobile-maps-location` | `useCurrentLocation(opts)` |
| Search locations | `mobile-maps-location` | `useLocationSearch(opts)` |
| Set up geofences | `mobile-maps-location` | `GeofenceManager.register(regions)` |

### UX Pattern Decision Tree

```
What UX moment are you building?
├── Data is loading → Skeleton loaders (mobile-skeleton-loaders)
│   ├── List of items → SkeletonRect rows with shimmer
│   ├── Profile/avatar → SkeletonCircle + SkeletonRect
│   └── Image card → SkeletonRect with borderRadius
├── First app launch → Onboarding (mobile-onboarding)
│   ├── Feature tour → OnboardingCarousel
│   └── Conditional flow → useOnboardingComplete + remote-config
├── Feature rollout → Remote config (mobile-remote-config)
│   ├── On/off toggle → useFeatureFlag
│   ├── A/B experiment → useExperimentVariant
│   └── Gradual rollout → useRolloutPercentage
├── User wants to share → Social sharing (mobile-social-sharing)
│   ├── Generic share → useShareContent (native sheet)
│   └── Specific platform → shareTo(platform, content)
└── Location-based feature → Maps (mobile-maps-location)
    ├── Show nearby items → MapView + MarkerCluster
    ├── Pick a location → useLocationSearch + geocode
    └── Proximity triggers → GeofenceManager
```

---

# Research Update: February 2026

| Technology | Version | Key Change |
|-----------|---------|------------|
| Expo SDK | 54.0.33 | React Native 0.81, React 19.1. Precompiled XCFrameworks (120s → 10s iOS builds). `expo-file-system/next` → `expo-file-system`. Icons must be square. |
| React Native | 0.84.0 | Hermes V1 default (10-15% TTI improvement). Legacy Architecture completely removed. Precompiled iOS binaries (8x faster builds). |
| Supabase | 2.95.3 | New API key model: `sb_publishable_` replaces anon key, `sb_secret_` replaces service_role. PostgREST v14 (20% more RPS). |

**Action items for this skill:**
- All libraries MUST support New Architecture (legacy bridge removed in RN 0.84)
- Update `expo-file-system` imports (old: `expo-file-system/next`, new: `expo-file-system`)
- Remove any `statusBar` references from `app.json` configs
- Ensure all icon assets are perfectly square
