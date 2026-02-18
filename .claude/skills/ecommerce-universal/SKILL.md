---
name: ecommerce-universal
description: "Production-ready e-commerce integration patterns covering Shopify Storefront API, WooCommerce REST API, headless commerce architecture, and common catalog/cart/checkout patterns. Use when: (1) Building e-commerce storefronts, (2) Integrating Shopify or WooCommerce APIs, (3) Implementing cart and checkout flows, (4) Designing product catalog data models, (5) Choosing an e-commerce platform, (6) Processing orders and webhooks, (7) Building headless commerce architecture. Triggers on 'e-commerce', 'Shopify', 'WooCommerce', 'storefront', 'product catalog', 'shopping cart', 'checkout flow', 'headless commerce', 'Medusa', 'Saleor', or 'online store'."
license: Proprietary
---

# E-Commerce Universal - Production Guide

**Multi-platform e-commerce integration with headless architecture patterns.**

Version: 1.0.0
Status: Production Ready
Platforms: Shopify, WooCommerce, Medusa, Saleor

---

## Table of Contents

1. [Overview](#overview)
2. [Platform Decision Matrix](#platform-decision-matrix)
3. [Shopify Storefront API](#shopify-storefront-api)
4. [WooCommerce REST API](#woocommerce-rest-api)
5. [Common Patterns](#common-patterns)
6. [Headless Commerce Architecture](#headless-commerce-architecture)
7. [Order Webhook Processing](#order-webhook-processing)
8. [Shipping & Tax Calculation](#shipping--tax-calculation)
9. [Testing Guide](#testing-guide)
10. [Troubleshooting](#troubleshooting)
11. [Integrates With](#integrates-with)

---

## Overview

### Why This Skill Exists

E-commerce applications share the same fundamental building blocks regardless of platform: product catalogs, carts, checkouts, orders, and fulfillment. This skill provides production-ready patterns for the two most popular platforms (Shopify, WooCommerce) and guidance on open-source alternatives (Medusa, Saleor), plus platform-agnostic patterns you can reuse everywhere.

### Critical Rules

- **NEVER** store full credit card numbers -- delegate to payment providers (see `payment-processing-universal` skill)
- **NEVER** trust client-side prices -- always validate against server-side catalog data
- **NEVER** skip webhook signature verification for order events
- **ALWAYS** use idempotency keys for order creation and payment capture
- **ALWAYS** handle currency as integers (cents) internally to avoid floating-point errors
- **ALWAYS** implement optimistic inventory checks at cart time, authoritative checks at checkout

### Quick Reference

| Operation | Shopify | WooCommerce |
|-----------|---------|-------------|
| Product query | Storefront GraphQL API | `/wp-json/wc/v3/products` |
| Cart management | `cartCreate` / `cartLinesAdd` mutations | Client-side or CoCart REST |
| Checkout | `checkoutCreate` mutation | `/wp-json/wc/v3/orders` + redirect |
| Webhooks | HMAC-SHA256 via `X-Shopify-Hmac-Sha256` | HMAC-SHA256 via `X-WC-Webhook-Signature` |
| Auth | Storefront Access Token (public) | Consumer Key + Secret (private) |

---

## Platform Decision Matrix

### When to Choose Which Platform

| Factor | Shopify | WooCommerce | Medusa | Saleor |
|--------|---------|-------------|--------|--------|
| **Best for** | Fastest launch, non-technical teams | WordPress sites, content-heavy stores | Full control, JS developers | GraphQL-first, Python developers |
| **Hosting** | Fully managed | Self-hosted (or managed WP) | Self-hosted (or Medusa Cloud) | Self-hosted (or Saleor Cloud) |
| **Pricing** | $39-399/mo + 0.5-2% tx fees | Free (plugin) + hosting costs | Free (OSS) + hosting costs | Free (OSS) + hosting costs |
| **API Style** | GraphQL (Storefront) + REST (Admin) | REST | REST + JS SDK | GraphQL |
| **Customization** | Limited (Liquid themes, apps) | Unlimited (PHP/hooks) | Unlimited (Node.js) | Unlimited (Python/Django) |
| **Scalability** | Handles any scale | Needs tuning at scale | Horizontal scaling | Horizontal scaling |
| **Ecosystem** | 8,000+ apps | 60,000+ plugins | Growing | Growing |
| **Headless support** | Excellent (Hydrogen/Oxygen) | Good (via headless plugins) | Native | Native |
| **Multi-currency** | Shopify Markets | Plugin required | Built-in | Built-in |
| **B2B features** | Shopify Plus only ($2,300/mo) | Plugin-based | Extensible | Built-in |

### Decision Flowchart

```
Need an online store?
├── Budget < $500/month AND non-technical team?
│   └── Shopify Basic ($39/mo)
├── Already on WordPress?
│   └── WooCommerce (free plugin + hosting)
├── Need full code control + JavaScript stack?
│   └── Medusa (open source)
├── Need full code control + Python/GraphQL stack?
│   └── Saleor (open source)
├── Enterprise with 100K+ SKUs?
│   ├── Shopify Plus ($2,300/mo) -- lowest ops burden
│   ├── Medusa/Saleor -- full control, higher ops burden
│   └── commercetools / BigCommerce Enterprise -- if budget allows
└── Marketplace (multi-vendor)?
    ├── Medusa with marketplace plugin
    └── Saleor with multi-tenant config
```

### Cost Comparison (10K orders/month)

| Platform | Monthly Cost | Transaction Fees | Total |
|----------|-------------|------------------|-------|
| Shopify Basic | $39 | 2.9% + $0.30/tx | ~$3,039 |
| Shopify (own gateway) | $79 | 0.5% + gateway fees | ~$579 + gateway |
| WooCommerce | ~$50 (hosting) | Gateway fees only | ~$50 + gateway |
| Medusa | ~$100 (infra) | Gateway fees only | ~$100 + gateway |
| Saleor | ~$100 (infra) | Gateway fees only | ~$100 + gateway |

---

## Shopify Storefront API

The Storefront API is a **public-facing** GraphQL API designed for building custom storefronts. It uses a **Storefront Access Token** (safe to expose in client-side code).

### Setup & Authentication

```typescript
// TypeScript: Shopify Storefront API client
const SHOPIFY_STORE_DOMAIN = process.env.SHOPIFY_STORE_DOMAIN!; // "mystore.myshopify.com"
const STOREFRONT_ACCESS_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN!;

interface ShopifyResponse<T> {
  data: T;
  errors?: Array<{ message: string; locations: Array<{ line: number; column: number }> }>;
}

async function shopifyStorefront<T>(
  query: string,
  variables: Record<string, unknown> = {}
): Promise<T> {
  const url = `https://${SHOPIFY_STORE_DOMAIN}/api/2024-01/graphql.json`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Storefront-Access-Token': STOREFRONT_ACCESS_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!response.ok) {
    throw new Error(`Shopify API error: ${response.status} ${response.statusText}`);
  }

  const json: ShopifyResponse<T> = await response.json();

  if (json.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${json.errors.map(e => e.message).join(', ')}`);
  }

  return json.data;
}
```

```python
# Python: Shopify Storefront API client
import os
import httpx
from typing import Any

SHOPIFY_STORE_DOMAIN = os.environ["SHOPIFY_STORE_DOMAIN"]
STOREFRONT_ACCESS_TOKEN = os.environ["SHOPIFY_STOREFRONT_TOKEN"]

async def shopify_storefront(query: str, variables: dict[str, Any] | None = None) -> dict:
    """Execute a Storefront API GraphQL query."""
    url = f"https://{SHOPIFY_STORE_DOMAIN}/api/2024-01/graphql.json"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            url,
            json={"query": query, "variables": variables or {}},
            headers={
                "Content-Type": "application/json",
                "X-Shopify-Storefront-Access-Token": STOREFRONT_ACCESS_TOKEN,
            },
        )
        response.raise_for_status()
        data = response.json()

        if errors := data.get("errors"):
            raise Exception(f"Shopify GraphQL errors: {errors}")

        return data["data"]
```

### Product Queries

```typescript
// Fetch products with variants, images, and pricing
const PRODUCTS_QUERY = `
  query GetProducts($first: Int!, $after: String, $query: String) {
    products(first: $first, after: $after, query: $query) {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        node {
          id
          title
          handle
          description
          descriptionHtml
          productType
          vendor
          tags
          availableForSale
          priceRange {
            minVariantPrice {
              amount
              currencyCode
            }
            maxVariantPrice {
              amount
              currencyCode
            }
          }
          compareAtPriceRange {
            minVariantPrice {
              amount
              currencyCode
            }
          }
          images(first: 10) {
            edges {
              node {
                id
                url
                altText
                width
                height
              }
            }
          }
          variants(first: 50) {
            edges {
              node {
                id
                title
                availableForSale
                quantityAvailable
                price {
                  amount
                  currencyCode
                }
                compareAtPrice {
                  amount
                  currencyCode
                }
                selectedOptions {
                  name
                  value
                }
                image {
                  url
                  altText
                }
              }
            }
          }
          metafields(identifiers: [
            { namespace: "custom", key: "material" },
            { namespace: "custom", key: "care_instructions" }
          ]) {
            key
            value
            type
          }
        }
      }
    }
  }
`;

// Single product by handle (URL slug)
const PRODUCT_BY_HANDLE_QUERY = `
  query GetProductByHandle($handle: String!) {
    productByHandle(handle: $handle) {
      id
      title
      handle
      description
      descriptionHtml
      availableForSale
      images(first: 10) {
        edges {
          node { id url altText width height }
        }
      }
      variants(first: 50) {
        edges {
          node {
            id
            title
            availableForSale
            quantityAvailable
            price { amount currencyCode }
            compareAtPrice { amount currencyCode }
            selectedOptions { name value }
          }
        }
      }
      seo { title description }
    }
  }
`;

// Usage
interface ProductsData {
  products: {
    pageInfo: { hasNextPage: boolean; endCursor: string | null };
    edges: Array<{ node: ShopifyProduct }>;
  };
}

async function getProducts(first = 20, after?: string, query?: string) {
  const data = await shopifyStorefront<ProductsData>(PRODUCTS_QUERY, {
    first,
    after,
    query, // e.g. "product_type:shoes AND available_for_sale:true"
  });
  return {
    products: data.products.edges.map(e => e.node),
    pageInfo: data.products.pageInfo,
  };
}
```

### Collection / Catalog Browsing

```typescript
// Browse collections (categories)
const COLLECTIONS_QUERY = `
  query GetCollections($first: Int!) {
    collections(first: $first) {
      edges {
        node {
          id
          title
          handle
          description
          image { url altText }
          products(first: 20) {
            edges {
              node {
                id
                title
                handle
                priceRange {
                  minVariantPrice { amount currencyCode }
                }
                images(first: 1) {
                  edges {
                    node { url altText }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

// Single collection with pagination and sorting
const COLLECTION_PRODUCTS_QUERY = `
  query GetCollectionProducts(
    $handle: String!
    $first: Int!
    $after: String
    $sortKey: ProductCollectionSortKeys
    $reverse: Boolean
    $filters: [ProductFilter!]
  ) {
    collectionByHandle(handle: $handle) {
      id
      title
      description
      products(
        first: $first
        after: $after
        sortKey: $sortKey
        reverse: $reverse
        filters: $filters
      ) {
        pageInfo { hasNextPage endCursor }
        filters {
          id
          label
          type
          values {
            id
            label
            count
            input
          }
        }
        edges {
          node {
            id title handle availableForSale
            priceRange {
              minVariantPrice { amount currencyCode }
            }
            images(first: 1) {
              edges { node { url altText } }
            }
            variants(first: 5) {
              edges {
                node {
                  id title availableForSale
                  price { amount currencyCode }
                  selectedOptions { name value }
                }
              }
            }
          }
        }
      }
    }
  }
`;

// Usage: fetch collection products with filters
async function getCollectionProducts(
  handle: string,
  options: {
    first?: number;
    after?: string;
    sortKey?: 'TITLE' | 'PRICE' | 'BEST_SELLING' | 'CREATED';
    reverse?: boolean;
    filters?: Array<{ productType?: string; price?: { min?: number; max?: number } }>;
  } = {}
) {
  const { first = 20, after, sortKey = 'BEST_SELLING', reverse = false, filters } = options;
  const data = await shopifyStorefront(COLLECTION_PRODUCTS_QUERY, {
    handle,
    first,
    after,
    sortKey,
    reverse,
    filters,
  });
  return data.collectionByHandle;
}
```

### Cart Management

Shopify's Storefront API uses a server-side cart model. The cart is created on Shopify's servers and referenced by a cart ID stored client-side.

```typescript
// --- Cart Types ---
interface CartLine {
  id: string;
  quantity: number;
  merchandise: {
    id: string;
    title: string;
    product: { title: string; handle: string };
    price: { amount: string; currencyCode: string };
    image?: { url: string; altText: string };
    selectedOptions: Array<{ name: string; value: string }>;
  };
  cost: {
    totalAmount: { amount: string; currencyCode: string };
  };
}

interface Cart {
  id: string;
  checkoutUrl: string;
  totalQuantity: number;
  cost: {
    subtotalAmount: { amount: string; currencyCode: string };
    totalTaxAmount: { amount: string; currencyCode: string };
    totalAmount: { amount: string; currencyCode: string };
  };
  lines: { edges: Array<{ node: CartLine }> };
}

// --- Cart Fragment (reusable) ---
const CART_FRAGMENT = `
  fragment CartFields on Cart {
    id
    checkoutUrl
    totalQuantity
    cost {
      subtotalAmount { amount currencyCode }
      totalTaxAmount { amount currencyCode }
      totalAmount { amount currencyCode }
    }
    lines(first: 100) {
      edges {
        node {
          id
          quantity
          merchandise {
            ... on ProductVariant {
              id
              title
              product { title handle }
              price { amount currencyCode }
              image { url altText }
              selectedOptions { name value }
            }
          }
          cost {
            totalAmount { amount currencyCode }
          }
        }
      }
    }
  }
`;

// --- Create Cart ---
const CREATE_CART = `
  mutation CartCreate($input: CartInput!) {
    cartCreate(input: $input) {
      cart { ...CartFields }
      userErrors { field message }
    }
  }
  ${CART_FRAGMENT}
`;

async function createCart(
  lines: Array<{ merchandiseId: string; quantity: number }>
): Promise<Cart> {
  const data = await shopifyStorefront<{ cartCreate: { cart: Cart; userErrors: any[] } }>(
    CREATE_CART,
    { input: { lines } }
  );
  if (data.cartCreate.userErrors.length > 0) {
    throw new Error(data.cartCreate.userErrors.map(e => e.message).join(', '));
  }
  return data.cartCreate.cart;
}

// --- Add Lines to Cart ---
const ADD_CART_LINES = `
  mutation CartLinesAdd($cartId: ID!, $lines: [CartLineInput!]!) {
    cartLinesAdd(cartId: $cartId, lines: $lines) {
      cart { ...CartFields }
      userErrors { field message }
    }
  }
  ${CART_FRAGMENT}
`;

async function addToCart(
  cartId: string,
  lines: Array<{ merchandiseId: string; quantity: number }>
): Promise<Cart> {
  const data = await shopifyStorefront<{ cartLinesAdd: { cart: Cart; userErrors: any[] } }>(
    ADD_CART_LINES,
    { cartId, lines }
  );
  return data.cartLinesAdd.cart;
}

// --- Update Cart Lines ---
const UPDATE_CART_LINES = `
  mutation CartLinesUpdate($cartId: ID!, $lines: [CartLineUpdateInput!]!) {
    cartLinesUpdate(cartId: $cartId, lines: $lines) {
      cart { ...CartFields }
      userErrors { field message }
    }
  }
  ${CART_FRAGMENT}
`;

async function updateCartLine(
  cartId: string,
  lineId: string,
  quantity: number
): Promise<Cart> {
  const data = await shopifyStorefront<{ cartLinesUpdate: { cart: Cart; userErrors: any[] } }>(
    UPDATE_CART_LINES,
    { cartId, lines: [{ id: lineId, quantity }] }
  );
  return data.cartLinesUpdate.cart;
}

// --- Remove Cart Lines ---
const REMOVE_CART_LINES = `
  mutation CartLinesRemove($cartId: ID!, $lineIds: [ID!]!) {
    cartLinesRemove(cartId: $cartId, lineIds: $lineIds) {
      cart { ...CartFields }
      userErrors { field message }
    }
  }
  ${CART_FRAGMENT}
`;

async function removeFromCart(cartId: string, lineIds: string[]): Promise<Cart> {
  const data = await shopifyStorefront<{ cartLinesRemove: { cart: Cart; userErrors: any[] } }>(
    REMOVE_CART_LINES,
    { cartId, lineIds }
  );
  return data.cartLinesRemove.cart;
}
```

### Checkout Flow

```typescript
// Shopify handles checkout on its own domain by default.
// For custom storefronts, use the cart's checkoutUrl or the Checkout API.

// Option 1: Redirect to Shopify-hosted checkout (simplest, recommended)
function redirectToCheckout(cart: Cart): void {
  // cart.checkoutUrl is ready to use -- redirect the customer
  window.location.href = cart.checkoutUrl;
}

// Option 2: Shopify Checkout API (for more control)
const CREATE_CHECKOUT = `
  mutation CheckoutCreate($input: CheckoutCreateInput!) {
    checkoutCreate(input: $input) {
      checkout {
        id
        webUrl
        totalPriceV2 { amount currencyCode }
        lineItems(first: 50) {
          edges {
            node {
              title
              quantity
              variant {
                price { amount currencyCode }
              }
            }
          }
        }
      }
      checkoutUserErrors { field message code }
    }
  }
`;

// Add shipping address
const CHECKOUT_SHIPPING_ADDRESS = `
  mutation CheckoutShippingAddressUpdate(
    $checkoutId: ID!
    $shippingAddress: MailingAddressInput!
  ) {
    checkoutShippingAddressUpdateV2(
      checkoutId: $checkoutId
      shippingAddress: $shippingAddress
    ) {
      checkout {
        id
        availableShippingRates {
          ready
          shippingRates {
            handle
            title
            price { amount currencyCode }
          }
        }
      }
      checkoutUserErrors { field message code }
    }
  }
`;

// Select shipping rate
const CHECKOUT_SHIPPING_LINE = `
  mutation CheckoutShippingLineUpdate($checkoutId: ID!, $shippingRateHandle: String!) {
    checkoutShippingLineUpdate(
      checkoutId: $checkoutId
      shippingRateHandle: $shippingRateHandle
    ) {
      checkout {
        id
        totalPriceV2 { amount currencyCode }
        shippingLine {
          title
          price { amount currencyCode }
        }
      }
      checkoutUserErrors { field message code }
    }
  }
`;

// Complete checkout with payment
const CHECKOUT_COMPLETE = `
  mutation CheckoutCompleteWithTokenizedPayment(
    $checkoutId: ID!
    $payment: TokenizedPaymentInputV3!
  ) {
    checkoutCompleteWithTokenizedPaymentV3(
      checkoutId: $checkoutId
      payment: $payment
    ) {
      checkout {
        id
        order { id orderNumber }
      }
      checkoutUserErrors { field message code }
      payment {
        id
        errorMessage
        ready
      }
    }
  }
`;

// Full checkout flow orchestration
async function completeCheckoutFlow(
  cartItems: Array<{ variantId: string; quantity: number }>,
  shippingAddress: ShippingAddress,
  paymentToken: string
) {
  // Step 1: Create checkout
  const { checkoutCreate } = await shopifyStorefront(CREATE_CHECKOUT, {
    input: {
      lineItems: cartItems.map(item => ({
        variantId: item.variantId,
        quantity: item.quantity,
      })),
    },
  });
  const checkoutId = checkoutCreate.checkout.id;

  // Step 2: Set shipping address
  const { checkoutShippingAddressUpdateV2 } = await shopifyStorefront(
    CHECKOUT_SHIPPING_ADDRESS,
    { checkoutId, shippingAddress }
  );

  // Step 3: Wait for shipping rates then select
  // (may need to poll -- rates calculate asynchronously)
  let rates = checkoutShippingAddressUpdateV2.checkout.availableShippingRates;
  while (!rates.ready) {
    await new Promise(r => setTimeout(r, 1000));
    const poll = await shopifyStorefront(/* re-query checkout for rates */);
    rates = poll.node.availableShippingRates;
  }

  // Step 4: Select shipping rate
  const cheapestRate = rates.shippingRates[0];
  await shopifyStorefront(CHECKOUT_SHIPPING_LINE, {
    checkoutId,
    shippingRateHandle: cheapestRate.handle,
  });

  // Step 5: Complete with payment (see payment-processing-universal skill)
  const { checkoutCompleteWithTokenizedPaymentV3 } = await shopifyStorefront(
    CHECKOUT_COMPLETE,
    {
      checkoutId,
      payment: {
        paymentAmount: { amount: "99.99", currencyCode: "USD" },
        idempotencyKey: crypto.randomUUID(),
        billingAddress: shippingAddress,
        type: "SHOPIFY_PAY",
        paymentData: paymentToken,
      },
    }
  );

  return checkoutCompleteWithTokenizedPaymentV3;
}
```

---

## WooCommerce REST API

WooCommerce uses a REST API authenticated with **Consumer Key + Consumer Secret** (OAuth 1.0a-style). The API runs on top of the WordPress REST API.

### Setup & Authentication

```typescript
// TypeScript: WooCommerce REST API client
import crypto from 'crypto';

const WC_BASE_URL = process.env.WC_BASE_URL!; // "https://mystore.com"
const WC_CONSUMER_KEY = process.env.WC_CONSUMER_KEY!;
const WC_CONSUMER_SECRET = process.env.WC_CONSUMER_SECRET!;

interface WooCommerceRequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: Record<string, unknown>;
  params?: Record<string, string | number | boolean>;
}

async function woocommerce<T>(
  endpoint: string,
  options: WooCommerceRequestOptions = {}
): Promise<T> {
  const { method = 'GET', body, params = {} } = options;

  const url = new URL(`${WC_BASE_URL}/wp-json/wc/v3/${endpoint}`);

  // Add query params
  Object.entries(params).forEach(([key, value]) => {
    url.searchParams.set(key, String(value));
  });

  // Basic auth (HTTPS required)
  const auth = Buffer.from(`${WC_CONSUMER_KEY}:${WC_CONSUMER_SECRET}`).toString('base64');

  const response = await fetch(url.toString(), {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Basic ${auth}`,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(
      `WooCommerce API error ${response.status}: ${error.message || response.statusText}`
    );
  }

  // Extract pagination headers
  const totalItems = response.headers.get('X-WP-Total');
  const totalPages = response.headers.get('X-WP-TotalPages');

  const data = await response.json();

  // Attach pagination metadata
  if (Array.isArray(data)) {
    (data as any)._pagination = {
      total: totalItems ? parseInt(totalItems) : undefined,
      totalPages: totalPages ? parseInt(totalPages) : undefined,
    };
  }

  return data as T;
}
```

```python
# Python: WooCommerce REST API client
import os
import httpx
from base64 import b64encode
from typing import Any

WC_BASE_URL = os.environ["WC_BASE_URL"]
WC_CONSUMER_KEY = os.environ["WC_CONSUMER_KEY"]
WC_CONSUMER_SECRET = os.environ["WC_CONSUMER_SECRET"]

class WooCommerceClient:
    """WooCommerce REST API client with pagination support."""

    def __init__(self):
        credentials = b64encode(
            f"{WC_CONSUMER_KEY}:{WC_CONSUMER_SECRET}".encode()
        ).decode()
        self.client = httpx.AsyncClient(
            base_url=f"{WC_BASE_URL}/wp-json/wc/v3",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {credentials}",
            },
            timeout=30.0,
        )

    async def get(self, endpoint: str, params: dict | None = None) -> dict | list:
        response = await self.client.get(f"/{endpoint}", params=params or {})
        response.raise_for_status()
        return response.json()

    async def post(self, endpoint: str, data: dict) -> dict:
        response = await self.client.post(f"/{endpoint}", json=data)
        response.raise_for_status()
        return response.json()

    async def put(self, endpoint: str, data: dict) -> dict:
        response = await self.client.put(f"/{endpoint}", json=data)
        response.raise_for_status()
        return response.json()

    async def delete(self, endpoint: str, force: bool = False) -> dict:
        response = await self.client.delete(
            f"/{endpoint}", params={"force": str(force).lower()}
        )
        response.raise_for_status()
        return response.json()

    async def get_all_pages(self, endpoint: str, params: dict | None = None) -> list:
        """Fetch all pages of a paginated endpoint."""
        all_items = []
        page = 1
        params = params or {}

        while True:
            params["page"] = page
            params["per_page"] = 100
            response = await self.client.get(f"/{endpoint}", params=params)
            response.raise_for_status()
            items = response.json()

            if not items:
                break

            all_items.extend(items)
            total_pages = int(response.headers.get("X-WP-TotalPages", 1))

            if page >= total_pages:
                break
            page += 1

        return all_items

wc = WooCommerceClient()
```

### Product CRUD

```typescript
// --- Product Types ---
interface WCProduct {
  id: number;
  name: string;
  slug: string;
  type: 'simple' | 'variable' | 'grouped' | 'external';
  status: 'publish' | 'draft' | 'pending' | 'private';
  description: string;
  short_description: string;
  sku: string;
  price: string;
  regular_price: string;
  sale_price: string;
  on_sale: boolean;
  stock_quantity: number | null;
  stock_status: 'instock' | 'outofstock' | 'onbackorder';
  manage_stock: boolean;
  categories: Array<{ id: number; name: string; slug: string }>;
  tags: Array<{ id: number; name: string; slug: string }>;
  images: Array<{ id: number; src: string; alt: string }>;
  attributes: Array<{
    id: number;
    name: string;
    options: string[];
    variation: boolean;
  }>;
  variations: number[];
  meta_data: Array<{ key: string; value: string }>;
}

// --- List Products (with filtering) ---
async function getProducts(options: {
  page?: number;
  per_page?: number;
  search?: string;
  category?: number;
  tag?: number;
  status?: string;
  min_price?: string;
  max_price?: string;
  orderby?: 'date' | 'title' | 'price' | 'popularity' | 'rating';
  order?: 'asc' | 'desc';
  on_sale?: boolean;
  stock_status?: 'instock' | 'outofstock' | 'onbackorder';
} = {}): Promise<WCProduct[]> {
  return woocommerce<WCProduct[]>('products', { params: options as any });
}

// --- Create Product ---
async function createProduct(product: {
  name: string;
  type?: 'simple' | 'variable';
  regular_price?: string;
  description?: string;
  short_description?: string;
  sku?: string;
  categories?: Array<{ id: number }>;
  images?: Array<{ src: string; alt?: string }>;
  manage_stock?: boolean;
  stock_quantity?: number;
  attributes?: Array<{
    name: string;
    options: string[];
    visible?: boolean;
    variation?: boolean;
  }>;
}): Promise<WCProduct> {
  return woocommerce<WCProduct>('products', {
    method: 'POST',
    body: product,
  });
}

// --- Update Product ---
async function updateProduct(
  id: number,
  updates: Partial<WCProduct>
): Promise<WCProduct> {
  return woocommerce<WCProduct>(`products/${id}`, {
    method: 'PUT',
    body: updates,
  });
}

// --- Delete Product ---
async function deleteProduct(id: number, force = false): Promise<WCProduct> {
  return woocommerce<WCProduct>(`products/${id}`, {
    method: 'DELETE',
    params: { force },
  });
}

// --- Batch Operations (create/update/delete up to 100 at a time) ---
async function batchProducts(operations: {
  create?: Array<Partial<WCProduct>>;
  update?: Array<Partial<WCProduct> & { id: number }>;
  delete?: number[];
}) {
  return woocommerce('products/batch', {
    method: 'POST',
    body: operations,
  });
}

// --- Product Variations (for variable products) ---
async function createVariation(
  productId: number,
  variation: {
    regular_price: string;
    sku?: string;
    stock_quantity?: number;
    manage_stock?: boolean;
    attributes: Array<{ name: string; option: string }>;
    image?: { src: string };
  }
) {
  return woocommerce(`products/${productId}/variations`, {
    method: 'POST',
    body: variation,
  });
}
```

### Order Management

```typescript
// --- Order Types ---
interface WCOrder {
  id: number;
  number: string;
  status: 'pending' | 'processing' | 'on-hold' | 'completed' | 'cancelled' | 'refunded' | 'failed';
  total: string;
  currency: string;
  billing: WCAddress;
  shipping: WCAddress;
  line_items: Array<{
    id: number;
    product_id: number;
    variation_id: number;
    name: string;
    quantity: number;
    price: number;
    sku: string;
    total: string;
  }>;
  shipping_lines: Array<{
    method_id: string;
    method_title: string;
    total: string;
  }>;
  payment_method: string;
  payment_method_title: string;
  transaction_id: string;
  date_created: string;
  date_modified: string;
  customer_id: number;
  meta_data: Array<{ key: string; value: string }>;
}

// --- List Orders ---
async function getOrders(options: {
  page?: number;
  per_page?: number;
  status?: string;
  customer?: number;
  after?: string;  // ISO 8601 date
  before?: string;
} = {}): Promise<WCOrder[]> {
  return woocommerce<WCOrder[]>('orders', { params: options as any });
}

// --- Create Order (programmatic) ---
async function createOrder(order: {
  payment_method: string;
  payment_method_title: string;
  set_paid?: boolean;
  billing: WCAddress;
  shipping: WCAddress;
  line_items: Array<{
    product_id: number;
    variation_id?: number;
    quantity: number;
  }>;
  shipping_lines?: Array<{
    method_id: string;
    method_title: string;
    total: string;
  }>;
  coupon_lines?: Array<{ code: string }>;
  meta_data?: Array<{ key: string; value: string }>;
}): Promise<WCOrder> {
  return woocommerce<WCOrder>('orders', {
    method: 'POST',
    body: order,
  });
}

// --- Update Order Status ---
async function updateOrderStatus(
  orderId: number,
  status: WCOrder['status'],
  note?: string
): Promise<WCOrder> {
  const updates: Record<string, unknown> = { status };

  // Optionally add an order note
  if (note) {
    await woocommerce(`orders/${orderId}/notes`, {
      method: 'POST',
      body: { note, customer_note: false },
    });
  }

  return woocommerce<WCOrder>(`orders/${orderId}`, {
    method: 'PUT',
    body: updates,
  });
}

// --- Refund Order ---
async function refundOrder(
  orderId: number,
  amount: string,
  reason: string,
  lineItems?: Array<{ id: number; quantity: number; refund_total: string }>
) {
  return woocommerce(`orders/${orderId}/refunds`, {
    method: 'POST',
    body: {
      amount,
      reason,
      line_items: lineItems,
      api_refund: true, // Automatically refund via payment gateway
    },
  });
}
```

### Customer Management

```typescript
// --- Customer Types ---
interface WCCustomer {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
  username: string;
  billing: WCAddress;
  shipping: WCAddress;
  orders_count: number;
  total_spent: string;
  date_created: string;
  meta_data: Array<{ key: string; value: string }>;
}

// --- Create Customer ---
async function createCustomer(customer: {
  email: string;
  first_name: string;
  last_name: string;
  username?: string;
  password?: string;
  billing?: Partial<WCAddress>;
  shipping?: Partial<WCAddress>;
}): Promise<WCCustomer> {
  return woocommerce<WCCustomer>('customers', {
    method: 'POST',
    body: customer,
  });
}

// --- Search Customers ---
async function searchCustomers(
  query: string,
  options: { page?: number; per_page?: number } = {}
): Promise<WCCustomer[]> {
  return woocommerce<WCCustomer[]>('customers', {
    params: { search: query, ...options } as any,
  });
}

// --- Customer Order History ---
async function getCustomerOrders(customerId: number): Promise<WCOrder[]> {
  return woocommerce<WCOrder[]>('orders', {
    params: { customer: customerId, per_page: 100 },
  });
}
```

### Webhook Integration

```typescript
// --- Register a WooCommerce Webhook ---
async function createWebhook(webhook: {
  name: string;
  topic: string;    // e.g. "order.created", "product.updated", "customer.created"
  delivery_url: string;
  secret: string;
  status?: 'active' | 'paused' | 'disabled';
}) {
  return woocommerce('webhooks', {
    method: 'POST',
    body: webhook,
  });
}

// Common webhook topics:
// order.created, order.updated, order.deleted, order.restored
// product.created, product.updated, product.deleted
// customer.created, customer.updated, customer.deleted
// coupon.created, coupon.updated, coupon.deleted

// --- Webhook Handler (Express) ---
import express from 'express';

function verifyWooCommerceWebhook(
  payload: string,
  signature: string,
  secret: string
): boolean {
  const computed = crypto
    .createHmac('sha256', secret)
    .update(payload, 'utf8')
    .digest('base64');
  return crypto.timingSafeEqual(
    Buffer.from(computed),
    Buffer.from(signature)
  );
}

const app = express();

app.post('/webhooks/woocommerce', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['x-wc-webhook-signature'] as string;
  const topic = req.headers['x-wc-webhook-topic'] as string;
  const source = req.headers['x-wc-webhook-source'] as string;

  // Verify signature
  if (!verifyWooCommerceWebhook(req.body.toString(), signature, WC_WEBHOOK_SECRET)) {
    console.error('Invalid WooCommerce webhook signature');
    return res.status(401).send('Invalid signature');
  }

  const data = JSON.parse(req.body.toString());

  // Route by topic
  switch (topic) {
    case 'order.created':
      handleNewOrder(data);
      break;
    case 'order.updated':
      handleOrderUpdate(data);
      break;
    case 'product.updated':
      invalidateProductCache(data.id);
      break;
    default:
      console.log(`Unhandled webhook topic: ${topic}`);
  }

  // Always respond 200 quickly (process async)
  res.status(200).send('OK');
});
```

```python
# Python: WooCommerce webhook handler (FastAPI)
import hmac
import hashlib
import base64
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

WC_WEBHOOK_SECRET = os.environ["WC_WEBHOOK_SECRET"]

def verify_wc_webhook(payload: bytes, signature: str, secret: str) -> bool:
    """Verify WooCommerce webhook HMAC-SHA256 signature."""
    computed = base64.b64encode(
        hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(computed, signature)

@app.post("/webhooks/woocommerce")
async def woocommerce_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-WC-Webhook-Signature", "")
    topic = request.headers.get("X-WC-Webhook-Topic", "")

    if not verify_wc_webhook(body, signature, WC_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()

    if topic == "order.created":
        await handle_new_order(data)
    elif topic == "order.updated":
        await handle_order_update(data)
    elif topic == "product.updated":
        await invalidate_product_cache(data["id"])

    return {"status": "ok"}
```

---

## Common Patterns

### Product Catalog Data Modeling

A platform-agnostic product model that normalizes across Shopify, WooCommerce, and custom databases.

```typescript
// --- Normalized Product Model ---
interface Product {
  id: string;                    // Platform-specific ID (string for Shopify GIDs)
  externalId?: string;           // Original platform ID
  platform: 'shopify' | 'woocommerce' | 'custom';

  // Core fields
  name: string;
  slug: string;                  // URL-safe handle
  description: string;
  descriptionHtml?: string;

  // Classification
  type: 'simple' | 'variable' | 'bundle' | 'digital' | 'subscription';
  categories: Category[];
  tags: string[];
  vendor?: string;

  // Pricing
  price: Money;                  // Current price (sale or regular)
  compareAtPrice?: Money;        // Original price if on sale

  // Media
  images: ProductImage[];

  // Availability
  availableForSale: boolean;
  totalInventory: number | null; // null = unlimited / not tracked

  // Variants
  options: ProductOption[];      // e.g. [{ name: "Size", values: ["S","M","L"] }]
  variants: ProductVariant[];

  // SEO
  seo: {
    title: string;
    description: string;
  };

  // Metadata
  metafields: Record<string, string>;

  // Timestamps
  createdAt: string;
  updatedAt: string;
}

interface Money {
  amount: number;      // In cents (integer!) to avoid floating-point issues
  currencyCode: string; // ISO 4217
}

interface ProductVariant {
  id: string;
  sku: string;
  name: string;       // e.g. "Red / Large"
  price: Money;
  compareAtPrice?: Money;
  inventory: number | null;
  availableForSale: boolean;
  options: Record<string, string>; // e.g. { "Color": "Red", "Size": "Large" }
  image?: ProductImage;
  weight?: { value: number; unit: 'kg' | 'lb' | 'g' | 'oz' };
}

interface ProductOption {
  name: string;        // e.g. "Color"
  values: string[];    // e.g. ["Red", "Blue", "Green"]
}

interface Category {
  id: string;
  name: string;
  slug: string;
  parentId?: string;
}

interface ProductImage {
  id: string;
  url: string;
  altText: string;
  width: number;
  height: number;
}

// --- Platform Normalizer ---
function normalizeShopifyProduct(shopifyProduct: any): Product {
  return {
    id: shopifyProduct.id,
    platform: 'shopify',
    name: shopifyProduct.title,
    slug: shopifyProduct.handle,
    description: shopifyProduct.description,
    descriptionHtml: shopifyProduct.descriptionHtml,
    type: shopifyProduct.variants.edges.length > 1 ? 'variable' : 'simple',
    categories: [], // Shopify uses collections, map separately
    tags: shopifyProduct.tags,
    vendor: shopifyProduct.vendor,
    price: {
      amount: Math.round(parseFloat(shopifyProduct.priceRange.minVariantPrice.amount) * 100),
      currencyCode: shopifyProduct.priceRange.minVariantPrice.currencyCode,
    },
    compareAtPrice: shopifyProduct.compareAtPriceRange?.minVariantPrice?.amount
      ? {
          amount: Math.round(parseFloat(shopifyProduct.compareAtPriceRange.minVariantPrice.amount) * 100),
          currencyCode: shopifyProduct.compareAtPriceRange.minVariantPrice.currencyCode,
        }
      : undefined,
    images: shopifyProduct.images.edges.map((e: any) => ({
      id: e.node.id,
      url: e.node.url,
      altText: e.node.altText || '',
      width: e.node.width,
      height: e.node.height,
    })),
    availableForSale: shopifyProduct.availableForSale,
    totalInventory: null,
    options: shopifyProduct.options || [],
    variants: shopifyProduct.variants.edges.map((e: any) => ({
      id: e.node.id,
      sku: e.node.sku || '',
      name: e.node.title,
      price: {
        amount: Math.round(parseFloat(e.node.price.amount) * 100),
        currencyCode: e.node.price.currencyCode,
      },
      inventory: e.node.quantityAvailable,
      availableForSale: e.node.availableForSale,
      options: Object.fromEntries(
        e.node.selectedOptions.map((o: any) => [o.name, o.value])
      ),
    })),
    seo: shopifyProduct.seo || { title: shopifyProduct.title, description: '' },
    metafields: {},
    createdAt: shopifyProduct.createdAt,
    updatedAt: shopifyProduct.updatedAt,
  };
}

function normalizeWooProduct(wcProduct: WCProduct): Product {
  return {
    id: String(wcProduct.id),
    platform: 'woocommerce',
    name: wcProduct.name,
    slug: wcProduct.slug,
    description: wcProduct.description,
    type: wcProduct.type === 'variable' ? 'variable' : 'simple',
    categories: wcProduct.categories.map(c => ({
      id: String(c.id),
      name: c.name,
      slug: c.slug,
    })),
    tags: wcProduct.tags.map(t => t.name),
    price: {
      amount: Math.round(parseFloat(wcProduct.price) * 100),
      currencyCode: 'USD', // WooCommerce stores currency in settings
    },
    compareAtPrice: wcProduct.on_sale && wcProduct.regular_price
      ? { amount: Math.round(parseFloat(wcProduct.regular_price) * 100), currencyCode: 'USD' }
      : undefined,
    images: wcProduct.images.map(img => ({
      id: String(img.id),
      url: img.src,
      altText: img.alt || '',
      width: 0,
      height: 0,
    })),
    availableForSale: wcProduct.stock_status === 'instock',
    totalInventory: wcProduct.stock_quantity,
    options: wcProduct.attributes
      .filter(a => a.variation)
      .map(a => ({ name: a.name, values: a.options })),
    variants: [], // Loaded separately via /products/{id}/variations
    seo: { title: wcProduct.name, description: wcProduct.short_description },
    metafields: Object.fromEntries(wcProduct.meta_data.map(m => [m.key, m.value])),
    createdAt: '',
    updatedAt: '',
  };
}
```

### Inventory Management & Sync

```typescript
// --- Inventory Tracking ---
interface InventoryUpdate {
  productId: string;
  variantId: string;
  sku: string;
  previousQuantity: number;
  newQuantity: number;
  reason: 'sale' | 'restock' | 'adjustment' | 'return' | 'damage';
  source: 'shopify' | 'woocommerce' | 'warehouse' | 'manual';
  timestamp: Date;
}

class InventoryManager {
  private redis: Redis;
  private db: Database;

  constructor(redis: Redis, db: Database) {
    this.redis = redis;
    this.db = db;
  }

  /**
   * Reserve inventory during checkout (optimistic lock with TTL).
   * Prevents overselling while the customer completes payment.
   */
  async reserveInventory(
    items: Array<{ variantId: string; quantity: number }>,
    reservationId: string,
    ttlSeconds = 600 // 10 minute reservation
  ): Promise<{ success: boolean; failedItems: string[] }> {
    const failedItems: string[] = [];

    // Use Redis transaction for atomic reservation
    const multi = this.redis.multi();

    for (const item of items) {
      const key = `inventory:${item.variantId}`;
      const reserved = `reserved:${item.variantId}`;

      // Check available = stock - reserved
      const stock = await this.redis.get(key);
      const currentReserved = await this.redis.get(reserved);
      const available = (parseInt(stock || '0')) - (parseInt(currentReserved || '0'));

      if (available < item.quantity) {
        failedItems.push(item.variantId);
        continue;
      }

      // Increment reserved count
      multi.incrby(reserved, item.quantity);
    }

    if (failedItems.length > 0) {
      return { success: false, failedItems };
    }

    await multi.exec();

    // Store reservation with TTL for auto-release
    await this.redis.setex(
      `reservation:${reservationId}`,
      ttlSeconds,
      JSON.stringify(items)
    );

    return { success: true, failedItems: [] };
  }

  /**
   * Confirm reservation after successful payment -- decrement actual stock.
   */
  async confirmReservation(reservationId: string): Promise<void> {
    const reservationData = await this.redis.get(`reservation:${reservationId}`);
    if (!reservationData) throw new Error('Reservation expired or not found');

    const items = JSON.parse(reservationData);

    for (const item of items) {
      // Decrement stock
      await this.redis.decrby(`inventory:${item.variantId}`, item.quantity);
      // Decrement reserved
      await this.redis.decrby(`reserved:${item.variantId}`, item.quantity);

      // Persist to database
      await this.db.query(
        `UPDATE product_variants SET stock_quantity = stock_quantity - $1 WHERE id = $2`,
        [item.quantity, item.variantId]
      );
    }

    await this.redis.del(`reservation:${reservationId}`);
  }

  /**
   * Release reservation if checkout is abandoned or payment fails.
   */
  async releaseReservation(reservationId: string): Promise<void> {
    const reservationData = await this.redis.get(`reservation:${reservationId}`);
    if (!reservationData) return; // Already expired

    const items = JSON.parse(reservationData);

    for (const item of items) {
      await this.redis.decrby(`reserved:${item.variantId}`, item.quantity);
    }

    await this.redis.del(`reservation:${reservationId}`);
  }

  /**
   * Sync inventory from external platform to local cache.
   */
  async syncFromPlatform(
    platform: 'shopify' | 'woocommerce',
    products: Array<{ variantId: string; quantity: number }>
  ): Promise<void> {
    const pipeline = this.redis.pipeline();

    for (const product of products) {
      pipeline.set(`inventory:${product.variantId}`, product.quantity);
    }

    await pipeline.exec();
  }
}
```

### Price Formatting & Currency Handling

```typescript
// --- Price Utilities ---

/**
 * CRITICAL: Always store prices as integers (cents/pence) internally.
 * Only format to decimal for display.
 */
interface Money {
  amount: number;       // Integer cents (e.g. 1999 = $19.99)
  currencyCode: string; // ISO 4217 (e.g. "USD", "EUR", "GBP")
}

// Currency configuration
const CURRENCY_CONFIG: Record<string, {
  symbol: string;
  decimalPlaces: number;  // Most are 2, JPY/KRW are 0
  symbolPosition: 'before' | 'after';
  thousandsSep: string;
  decimalSep: string;
}> = {
  USD: { symbol: '$', decimalPlaces: 2, symbolPosition: 'before', thousandsSep: ',', decimalSep: '.' },
  EUR: { symbol: '\u20AC', decimalPlaces: 2, symbolPosition: 'after', thousandsSep: '.', decimalSep: ',' },
  GBP: { symbol: '\u00A3', decimalPlaces: 2, symbolPosition: 'before', thousandsSep: ',', decimalSep: '.' },
  JPY: { symbol: '\u00A5', decimalPlaces: 0, symbolPosition: 'before', thousandsSep: ',', decimalSep: '.' },
  CAD: { symbol: 'CA$', decimalPlaces: 2, symbolPosition: 'before', thousandsSep: ',', decimalSep: '.' },
  AUD: { symbol: 'A$', decimalPlaces: 2, symbolPosition: 'before', thousandsSep: ',', decimalSep: '.' },
};

function formatPrice(money: Money, locale?: string): string {
  const config = CURRENCY_CONFIG[money.currencyCode];
  if (!config) {
    // Fallback: use Intl.NumberFormat
    return new Intl.NumberFormat(locale || 'en-US', {
      style: 'currency',
      currency: money.currencyCode,
    }).format(money.amount / 100);
  }

  const divisor = Math.pow(10, config.decimalPlaces);
  const value = money.amount / divisor;

  // Use Intl for reliable locale-aware formatting
  return new Intl.NumberFormat(locale || 'en-US', {
    style: 'currency',
    currency: money.currencyCode,
    minimumFractionDigits: config.decimalPlaces,
    maximumFractionDigits: config.decimalPlaces,
  }).format(value);
}

// Arithmetic helpers (all in cents)
function addMoney(a: Money, b: Money): Money {
  if (a.currencyCode !== b.currencyCode) {
    throw new Error(`Currency mismatch: ${a.currencyCode} vs ${b.currencyCode}`);
  }
  return { amount: a.amount + b.amount, currencyCode: a.currencyCode };
}

function multiplyMoney(money: Money, quantity: number): Money {
  return { amount: Math.round(money.amount * quantity), currencyCode: money.currencyCode };
}

function calculateDiscount(price: Money, percentOff: number): Money {
  const discount = Math.round(price.amount * (percentOff / 100));
  return { amount: price.amount - discount, currencyCode: price.currencyCode };
}

// Parse platform price strings to Money
function parseShopifyPrice(amount: string, currencyCode: string): Money {
  return {
    amount: Math.round(parseFloat(amount) * 100),
    currencyCode,
  };
}

function parseWooPrice(price: string, currencyCode = 'USD'): Money {
  return {
    amount: Math.round(parseFloat(price) * 100),
    currencyCode,
  };
}

// Usage
const price = { amount: 1999, currencyCode: 'USD' };
formatPrice(price);              // "$19.99"
formatPrice(price, 'de-DE');     // "19,99 $" (German locale)
```

```python
# Python: Price formatting
from decimal import Decimal, ROUND_HALF_UP
from dataclasses import dataclass
import locale as locale_mod

@dataclass(frozen=True)
class Money:
    """Immutable money value. Amount is always in minor units (cents)."""
    amount: int          # Cents
    currency_code: str   # ISO 4217

    @classmethod
    def from_string(cls, value: str, currency_code: str = "USD") -> "Money":
        """Parse a decimal string like '19.99' to Money(1999, 'USD')."""
        decimal_val = Decimal(value)
        cents = int((decimal_val * 100).to_integral_value(rounding=ROUND_HALF_UP))
        return cls(amount=cents, currency_code=currency_code)

    def to_decimal(self) -> Decimal:
        """Convert cents to decimal value."""
        return Decimal(self.amount) / Decimal(100)

    def format(self, locale_str: str = "en_US") -> str:
        """Format for display."""
        symbols = {"USD": "$", "EUR": "\u20AC", "GBP": "\u00A3", "JPY": "\u00A5"}
        symbol = symbols.get(self.currency_code, self.currency_code)

        if self.currency_code == "JPY":
            return f"{symbol}{self.amount:,}"

        decimal_val = self.to_decimal()
        return f"{symbol}{decimal_val:,.2f}"

    def __add__(self, other: "Money") -> "Money":
        if self.currency_code != other.currency_code:
            raise ValueError(f"Currency mismatch: {self.currency_code} vs {other.currency_code}")
        return Money(self.amount + other.amount, self.currency_code)

    def __mul__(self, quantity: int) -> "Money":
        return Money(round(self.amount * quantity), self.currency_code)

# Usage
price = Money.from_string("19.99", "USD")
print(price.format())    # $19.99
total = price * 3         # Money(5997, "USD") -> $59.97
```

### Cart State Management (React)

```tsx
// --- React Cart Context with localStorage persistence ---
import React, { createContext, useContext, useReducer, useEffect, useCallback } from 'react';

// Types
interface CartItem {
  variantId: string;
  productId: string;
  name: string;
  variantName: string;
  price: Money;
  quantity: number;
  image?: string;
  maxQuantity?: number; // Inventory limit
}

interface CartState {
  items: CartItem[];
  platformCartId: string | null; // Shopify cart ID or WooCommerce session
  isLoading: boolean;
  error: string | null;
}

type CartAction =
  | { type: 'SET_CART'; payload: CartState }
  | { type: 'ADD_ITEM'; payload: CartItem }
  | { type: 'UPDATE_QUANTITY'; payload: { variantId: string; quantity: number } }
  | { type: 'REMOVE_ITEM'; payload: { variantId: string } }
  | { type: 'CLEAR_CART' }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_PLATFORM_CART_ID'; payload: string };

// Reducer
function cartReducer(state: CartState, action: CartAction): CartState {
  switch (action.type) {
    case 'SET_CART':
      return action.payload;

    case 'ADD_ITEM': {
      const existing = state.items.find(i => i.variantId === action.payload.variantId);
      if (existing) {
        const newQty = existing.quantity + action.payload.quantity;
        const maxQty = existing.maxQuantity ?? Infinity;
        return {
          ...state,
          items: state.items.map(i =>
            i.variantId === action.payload.variantId
              ? { ...i, quantity: Math.min(newQty, maxQty) }
              : i
          ),
        };
      }
      return { ...state, items: [...state.items, action.payload] };
    }

    case 'UPDATE_QUANTITY': {
      if (action.payload.quantity <= 0) {
        return {
          ...state,
          items: state.items.filter(i => i.variantId !== action.payload.variantId),
        };
      }
      return {
        ...state,
        items: state.items.map(i =>
          i.variantId === action.payload.variantId
            ? { ...i, quantity: Math.min(action.payload.quantity, i.maxQuantity ?? Infinity) }
            : i
        ),
      };
    }

    case 'REMOVE_ITEM':
      return {
        ...state,
        items: state.items.filter(i => i.variantId !== action.payload.variantId),
      };

    case 'CLEAR_CART':
      return { ...state, items: [], platformCartId: null };

    case 'SET_LOADING':
      return { ...state, isLoading: action.payload };

    case 'SET_ERROR':
      return { ...state, error: action.payload };

    case 'SET_PLATFORM_CART_ID':
      return { ...state, platformCartId: action.payload };

    default:
      return state;
  }
}

// Computed values
function getCartTotals(items: CartItem[]) {
  const subtotal = items.reduce(
    (sum, item) => sum + item.price.amount * item.quantity,
    0
  );
  const totalItems = items.reduce((sum, item) => sum + item.quantity, 0);
  const currencyCode = items[0]?.price.currencyCode || 'USD';

  return {
    subtotal: { amount: subtotal, currencyCode } as Money,
    totalItems,
    isEmpty: items.length === 0,
  };
}

// Storage key
const CART_STORAGE_KEY = 'ecommerce_cart';

// Initial state
const initialCartState: CartState = {
  items: [],
  platformCartId: null,
  isLoading: false,
  error: null,
};

// Context
interface CartContextValue {
  state: CartState;
  totals: ReturnType<typeof getCartTotals>;
  addItem: (item: CartItem) => void;
  updateQuantity: (variantId: string, quantity: number) => void;
  removeItem: (variantId: string) => void;
  clearCart: () => void;
}

const CartContext = createContext<CartContextValue | null>(null);

// Provider
export function CartProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(cartReducer, initialCartState, () => {
    // Load from localStorage on init
    if (typeof window === 'undefined') return initialCartState;
    try {
      const saved = localStorage.getItem(CART_STORAGE_KEY);
      return saved ? { ...initialCartState, ...JSON.parse(saved) } : initialCartState;
    } catch {
      return initialCartState;
    }
  });

  // Persist to localStorage on change
  useEffect(() => {
    try {
      localStorage.setItem(
        CART_STORAGE_KEY,
        JSON.stringify({ items: state.items, platformCartId: state.platformCartId })
      );
    } catch {
      // localStorage full or unavailable
    }
  }, [state.items, state.platformCartId]);

  const totals = getCartTotals(state.items);

  const addItem = useCallback((item: CartItem) => {
    dispatch({ type: 'ADD_ITEM', payload: item });
  }, []);

  const updateQuantity = useCallback((variantId: string, quantity: number) => {
    dispatch({ type: 'UPDATE_QUANTITY', payload: { variantId, quantity } });
  }, []);

  const removeItem = useCallback((variantId: string) => {
    dispatch({ type: 'REMOVE_ITEM', payload: { variantId } });
  }, []);

  const clearCart = useCallback(() => {
    dispatch({ type: 'CLEAR_CART' });
  }, []);

  return (
    <CartContext.Provider value={{ state, totals, addItem, updateQuantity, removeItem, clearCart }}>
      {children}
    </CartContext.Provider>
  );
}

// Hook
export function useCart(): CartContextValue {
  const context = useContext(CartContext);
  if (!context) throw new Error('useCart must be used within CartProvider');
  return context;
}

// Usage in component
function AddToCartButton({ product, variant }: { product: Product; variant: ProductVariant }) {
  const { addItem } = useCart();

  return (
    <button
      onClick={() =>
        addItem({
          variantId: variant.id,
          productId: product.id,
          name: product.name,
          variantName: variant.name,
          price: variant.price,
          quantity: 1,
          image: product.images[0]?.url,
          maxQuantity: variant.inventory ?? undefined,
        })
      }
      disabled={!variant.availableForSale}
    >
      {variant.availableForSale ? 'Add to Cart' : 'Out of Stock'}
    </button>
  );
}
```

### Checkout Flow UX Patterns

```
Checkout UX Best Practices:

1. GUEST CHECKOUT FIRST
   - Never force account creation before purchase
   - Offer "save info for next time" checkbox at the end
   - Guest checkout increases conversion by 20-30%

2. SINGLE PAGE vs MULTI-STEP
   ┌─────────────────────────────────────────────┐
   │ Single Page: Best for <5 items, simple       │
   │ Multi-Step:  Best for complex (shipping opts) │
   │                                               │
   │ Multi-step flow:                              │
   │ [Cart] → [Info] → [Shipping] → [Payment]     │
   │   ○────────●──────────○───────────○           │
   │          Step 2 of 4                          │
   └─────────────────────────────────────────────┘

3. PROGRESS INDICATOR
   - Always show which step the user is on
   - Allow going back without losing data
   - Show order summary sidebar at all steps

4. FORM OPTIMIZATION
   - Auto-detect country from IP for defaults
   - Address autocomplete (Google Places API)
   - "Same as shipping" checkbox for billing
   - Real-time validation (not just on submit)
   - Mobile-optimized: numeric keyboard for phone/zip

5. TRUST SIGNALS AT CHECKOUT
   - SSL badge / "Secure checkout"
   - Accepted payment icons
   - Money-back guarantee
   - Customer support contact
   - Return policy link

6. CART ABANDONMENT RECOVERY
   - Exit-intent popup with incentive (10% off)
   - Email recovery sequence (1hr, 24hr, 72hr)
   - Persistent cart (localStorage + server-side)
   - SMS recovery for mobile
```

### Search & Filtering (Faceted Search)

```typescript
// --- Product Search with Faceted Filtering ---
// For full search infrastructure, see `search-universal` skill

interface SearchFilters {
  query?: string;
  categories?: string[];
  priceRange?: { min: number; max: number }; // In cents
  attributes?: Record<string, string[]>;     // e.g. { "Color": ["Red", "Blue"] }
  inStock?: boolean;
  onSale?: boolean;
  sortBy?: 'relevance' | 'price_asc' | 'price_desc' | 'newest' | 'best_selling' | 'rating';
  page?: number;
  pageSize?: number;
}

interface SearchResult {
  products: Product[];
  total: number;
  facets: Facet[];
  pagination: {
    page: number;
    pageSize: number;
    totalPages: number;
  };
}

interface Facet {
  name: string;        // e.g. "Category", "Color", "Price Range"
  type: 'terms' | 'range' | 'boolean';
  values: FacetValue[];
}

interface FacetValue {
  value: string;
  label: string;
  count: number;
  selected: boolean;
}

// Elasticsearch-backed product search
async function searchProducts(filters: SearchFilters): Promise<SearchResult> {
  const {
    query,
    categories,
    priceRange,
    attributes,
    inStock,
    onSale,
    sortBy = 'relevance',
    page = 1,
    pageSize = 20,
  } = filters;

  // Build Elasticsearch query
  const must: any[] = [];
  const filter: any[] = [];

  if (query) {
    must.push({
      multi_match: {
        query,
        fields: ['name^3', 'description', 'tags^2', 'sku^4', 'vendor'],
        type: 'best_fields',
        fuzziness: 'AUTO',
      },
    });
  }

  if (categories?.length) {
    filter.push({ terms: { 'categories.slug': categories } });
  }

  if (priceRange) {
    filter.push({
      range: {
        'price.amount': {
          gte: priceRange.min,
          lte: priceRange.max,
        },
      },
    });
  }

  if (attributes) {
    for (const [attr, values] of Object.entries(attributes)) {
      filter.push({
        nested: {
          path: 'variants.options',
          query: {
            bool: {
              must: [
                { term: { 'variants.options.name': attr } },
                { terms: { 'variants.options.value': values } },
              ],
            },
          },
        },
      });
    }
  }

  if (inStock) {
    filter.push({ term: { availableForSale: true } });
  }

  if (onSale) {
    filter.push({ exists: { field: 'compareAtPrice' } });
  }

  // Sort mapping
  const sortMap: Record<string, any> = {
    relevance: '_score',
    price_asc: { 'price.amount': 'asc' },
    price_desc: { 'price.amount': 'desc' },
    newest: { createdAt: 'desc' },
    best_selling: { salesCount: 'desc' },
    rating: { averageRating: 'desc' },
  };

  const esQuery = {
    from: (page - 1) * pageSize,
    size: pageSize,
    query: {
      bool: {
        must: must.length > 0 ? must : [{ match_all: {} }],
        filter,
      },
    },
    sort: [sortMap[sortBy]],
    aggs: {
      categories: {
        terms: { field: 'categories.slug', size: 50 },
      },
      price_ranges: {
        range: {
          field: 'price.amount',
          ranges: [
            { key: 'Under $25', to: 2500 },
            { key: '$25 - $50', from: 2500, to: 5000 },
            { key: '$50 - $100', from: 5000, to: 10000 },
            { key: '$100 - $200', from: 10000, to: 20000 },
            { key: 'Over $200', from: 20000 },
          ],
        },
      },
      colors: {
        nested: { path: 'variants.options' },
        aggs: {
          color_values: {
            filter: { term: { 'variants.options.name': 'Color' } },
            aggs: {
              values: { terms: { field: 'variants.options.value', size: 20 } },
            },
          },
        },
      },
      in_stock: {
        filter: { term: { availableForSale: true } },
      },
      on_sale: {
        filter: { exists: { field: 'compareAtPrice' } },
      },
    },
  };

  const response = await esClient.search({
    index: 'products',
    body: esQuery,
  });

  return {
    products: response.hits.hits.map((hit: any) => hit._source),
    total: response.hits.total.value,
    facets: buildFacets(response.aggregations, filters),
    pagination: {
      page,
      pageSize,
      totalPages: Math.ceil(response.hits.total.value / pageSize),
    },
  };
}

// React hook for search with URL sync
function useProductSearch() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [results, setResults] = React.useState<SearchResult | null>(null);
  const [isLoading, setIsLoading] = React.useState(false);

  const filters: SearchFilters = React.useMemo(() => ({
    query: searchParams.get('q') || undefined,
    categories: searchParams.getAll('category'),
    priceRange: searchParams.get('minPrice')
      ? {
          min: parseInt(searchParams.get('minPrice')!),
          max: parseInt(searchParams.get('maxPrice') || '999999'),
        }
      : undefined,
    sortBy: (searchParams.get('sort') as SearchFilters['sortBy']) || 'relevance',
    page: parseInt(searchParams.get('page') || '1'),
    pageSize: 20,
  }), [searchParams]);

  useEffect(() => {
    const abortController = new AbortController();
    setIsLoading(true);

    searchProducts(filters)
      .then(setResults)
      .catch(console.error)
      .finally(() => setIsLoading(false));

    return () => abortController.abort();
  }, [filters]);

  const updateFilter = useCallback((key: string, value: string | string[] | undefined) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      next.delete(key);
      if (value !== undefined) {
        if (Array.isArray(value)) {
          value.forEach(v => next.append(key, v));
        } else {
          next.set(key, value);
        }
      }
      next.set('page', '1'); // Reset to first page on filter change
      return next;
    });
  }, [setSearchParams]);

  return { results, isLoading, filters, updateFilter };
}
```

---

## Headless Commerce Architecture

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND LAYER                        │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌────────┐ │
│  │ Next.js  │  │ Mobile   │  │   POS     │  │ Kiosk  │ │
│  │ Web App  │  │ App      │  │  Terminal │  │  App   │ │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  └───┬────┘ │
│       │              │              │             │      │
└───────┼──────────────┼──────────────┼─────────────┼──────┘
        │              │              │             │
        ▼              ▼              ▼             ▼
┌─────────────────────────────────────────────────────────┐
│                   API GATEWAY / BFF                      │
│  (Route, auth, rate limit, aggregate)                    │
│  See: unified-api-client module                          │
└──────────┬────────────┬────────────┬────────────────────┘
           │            │            │
    ┌──────▼──┐  ┌──────▼──┐  ┌─────▼────┐
    │ Commerce│  │ Payment │  │  Search  │
    │ Engine  │  │ Service │  │  Service │
    │         │  │         │  │          │
    │ Shopify │  │ Stripe  │  │ Algolia  │
    │   or    │  │ PayPal  │  │ Elastic  │
    │ Medusa  │  │         │  │          │
    └────┬────┘  └────┬────┘  └────┬─────┘
         │            │            │
    ┌────▼────┐  ┌────▼────┐  ┌───▼──────┐
    │ Product │  │ Payment │  │  Search  │
    │  Cache  │  │  Logs   │  │  Index   │
    │ (Redis) │  │  (DB)   │  │          │
    └─────────┘  └─────────┘  └──────────┘
```

### Next.js Headless Storefront (App Router)

```typescript
// app/products/[handle]/page.tsx
// Server Component -- fetches product at build/request time
import { notFound } from 'next/navigation';

interface ProductPageProps {
  params: { handle: string };
}

// SSG: Generate static pages for popular products
export async function generateStaticParams() {
  const products = await getProducts(100);
  return products.map(p => ({ handle: p.slug }));
}

export async function generateMetadata({ params }: ProductPageProps) {
  const product = await getProductByHandle(params.handle);
  if (!product) return {};

  return {
    title: product.seo.title || product.name,
    description: product.seo.description || product.description.slice(0, 160),
    openGraph: {
      images: product.images.map(img => ({ url: img.url, alt: img.altText })),
    },
  };
}

export default async function ProductPage({ params }: ProductPageProps) {
  const product = await getProductByHandle(params.handle);
  if (!product) notFound();

  // Structured data for SEO
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Product',
    name: product.name,
    description: product.description,
    image: product.images.map(img => img.url),
    offers: {
      '@type': 'AggregateOffer',
      lowPrice: formatPrice(product.price),
      priceCurrency: product.price.currencyCode,
      availability: product.availableForSale
        ? 'https://schema.org/InStock'
        : 'https://schema.org/OutOfStock',
    },
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <ProductDetail product={product} />
    </>
  );
}

// app/products/[handle]/product-detail.tsx
// Client Component -- handles interactive state (variant selection, add to cart)
'use client';

import { useState } from 'react';
import { useCart } from '@/lib/cart-context';

function ProductDetail({ product }: { product: Product }) {
  const [selectedOptions, setSelectedOptions] = useState<Record<string, string>>({});
  const { addItem } = useCart();

  // Find matching variant
  const selectedVariant = product.variants.find(v =>
    Object.entries(selectedOptions).every(([key, value]) => v.options[key] === value)
  ) || product.variants[0];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
      {/* Image gallery */}
      <ImageGallery images={product.images} />

      {/* Product info */}
      <div>
        <h1 className="text-3xl font-bold">{product.name}</h1>

        <div className="mt-4">
          <span className="text-2xl font-semibold">
            {formatPrice(selectedVariant.price)}
          </span>
          {selectedVariant.compareAtPrice && (
            <span className="ml-2 text-lg text-gray-500 line-through">
              {formatPrice(selectedVariant.compareAtPrice)}
            </span>
          )}
        </div>

        {/* Option selectors */}
        {product.options.map(option => (
          <div key={option.name} className="mt-4">
            <label className="font-medium">{option.name}</label>
            <div className="flex gap-2 mt-2">
              {option.values.map(value => (
                <button
                  key={value}
                  className={`px-4 py-2 border rounded ${
                    selectedOptions[option.name] === value
                      ? 'border-black bg-black text-white'
                      : 'border-gray-300'
                  }`}
                  onClick={() =>
                    setSelectedOptions(prev => ({ ...prev, [option.name]: value }))
                  }
                >
                  {value}
                </button>
              ))}
            </div>
          </div>
        ))}

        {/* Add to Cart */}
        <button
          className="mt-6 w-full py-3 bg-black text-white rounded-lg disabled:opacity-50"
          disabled={!selectedVariant.availableForSale}
          onClick={() =>
            addItem({
              variantId: selectedVariant.id,
              productId: product.id,
              name: product.name,
              variantName: selectedVariant.name,
              price: selectedVariant.price,
              quantity: 1,
              image: product.images[0]?.url,
              maxQuantity: selectedVariant.inventory ?? undefined,
            })
          }
        >
          {selectedVariant.availableForSale ? 'Add to Cart' : 'Out of Stock'}
        </button>

        {/* Description */}
        <div
          className="mt-8 prose"
          dangerouslySetInnerHTML={{ __html: product.descriptionHtml || product.description }}
        />
      </div>
    </div>
  );
}
```

### API Route: Backend-for-Frontend (BFF)

```typescript
// app/api/cart/route.ts
// Server-side cart operations that proxy to Shopify/WooCommerce
import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  const { action, ...payload } = await request.json();

  try {
    switch (action) {
      case 'create': {
        const cart = await createCart(payload.lines);
        return NextResponse.json({ cart });
      }
      case 'add': {
        const cart = await addToCart(payload.cartId, payload.lines);
        return NextResponse.json({ cart });
      }
      case 'update': {
        const cart = await updateCartLine(payload.cartId, payload.lineId, payload.quantity);
        return NextResponse.json({ cart });
      }
      case 'remove': {
        const cart = await removeFromCart(payload.cartId, payload.lineIds);
        return NextResponse.json({ cart });
      }
      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch (error) {
    console.error('Cart API error:', error);
    return NextResponse.json(
      { error: 'Failed to update cart' },
      { status: 500 }
    );
  }
}
```

### Caching Strategy for Product Catalogs

```typescript
// Product catalog caching layers
// For full caching infrastructure, see `caching-universal` skill

// Layer 1: ISR (Incremental Static Regeneration) via Next.js
// Product pages rebuild every 60 seconds automatically
export const revalidate = 60;

// Layer 2: Redis cache for API responses
async function getCachedProduct(handle: string): Promise<Product | null> {
  const cacheKey = `product:${handle}`;

  // Check Redis
  const cached = await redis.get(cacheKey);
  if (cached) return JSON.parse(cached);

  // Fetch from platform
  const product = await getProductByHandle(handle);
  if (!product) return null;

  // Cache for 5 minutes
  await redis.setex(cacheKey, 300, JSON.stringify(product));

  return product;
}

// Layer 3: CDN cache headers
// Set in Next.js API routes or middleware
function setCacheHeaders(response: NextResponse, maxAge = 60, staleWhileRevalidate = 300) {
  response.headers.set(
    'Cache-Control',
    `public, s-maxage=${maxAge}, stale-while-revalidate=${staleWhileRevalidate}`
  );
  return response;
}

// Invalidation: Webhook-triggered
async function handleProductUpdateWebhook(productId: string) {
  // Clear Redis cache
  const handle = await getProductHandle(productId);
  await redis.del(`product:${handle}`);

  // Trigger Next.js on-demand revalidation
  await fetch(`${process.env.NEXT_PUBLIC_URL}/api/revalidate`, {
    method: 'POST',
    headers: { 'x-revalidation-secret': process.env.REVALIDATION_SECRET! },
    body: JSON.stringify({ path: `/products/${handle}` }),
  });
}
```

---

## Order Webhook Processing

### Robust Webhook Handler

```typescript
// --- Production Webhook Processor ---
// Handles webhooks from Shopify and WooCommerce with:
// - Signature verification
// - Idempotency (deduplication)
// - Retry-safe processing
// - Dead letter queue for failures

import crypto from 'crypto';

interface WebhookEvent {
  id: string;
  source: 'shopify' | 'woocommerce';
  topic: string;
  payload: Record<string, unknown>;
  receivedAt: Date;
  signature: string;
}

class WebhookProcessor {
  private redis: Redis;
  private db: Database;
  private queue: JobQueue;

  constructor(redis: Redis, db: Database, queue: JobQueue) {
    this.redis = redis;
    this.db = db;
    this.queue = queue;
  }

  /**
   * Verify webhook authenticity.
   */
  verifySignature(event: WebhookEvent, rawBody: string): boolean {
    if (event.source === 'shopify') {
      const secret = process.env.SHOPIFY_WEBHOOK_SECRET!;
      const computed = crypto
        .createHmac('sha256', secret)
        .update(rawBody, 'utf8')
        .digest('base64');
      return crypto.timingSafeEqual(
        Buffer.from(computed),
        Buffer.from(event.signature)
      );
    }

    if (event.source === 'woocommerce') {
      const secret = process.env.WC_WEBHOOK_SECRET!;
      const computed = crypto
        .createHmac('sha256', secret)
        .update(rawBody, 'utf8')
        .digest('base64');
      return crypto.timingSafeEqual(
        Buffer.from(computed),
        Buffer.from(event.signature)
      );
    }

    return false;
  }

  /**
   * Process webhook with idempotency guard.
   */
  async process(event: WebhookEvent, rawBody: string): Promise<void> {
    // 1. Verify signature
    if (!this.verifySignature(event, rawBody)) {
      throw new Error(`Invalid webhook signature from ${event.source}`);
    }

    // 2. Idempotency check (prevent duplicate processing)
    const idempotencyKey = `webhook:${event.source}:${event.id}`;
    const alreadyProcessed = await this.redis.set(
      idempotencyKey,
      'processing',
      'EX',
      86400 * 7, // 7 day TTL
      'NX'       // Only set if not exists
    );

    if (!alreadyProcessed) {
      console.log(`Duplicate webhook skipped: ${idempotencyKey}`);
      return;
    }

    // 3. Log the raw event
    await this.db.query(
      `INSERT INTO webhook_events (id, source, topic, payload, received_at, status)
       VALUES ($1, $2, $3, $4, $5, 'processing')`,
      [event.id, event.source, event.topic, JSON.stringify(event.payload), event.receivedAt]
    );

    // 4. Route to handler
    try {
      await this.routeEvent(event);

      await this.db.query(
        `UPDATE webhook_events SET status = 'completed', processed_at = NOW() WHERE id = $1`,
        [event.id]
      );
      await this.redis.set(idempotencyKey, 'completed', 'EX', 86400 * 7);
    } catch (error) {
      // Mark as failed, queue for retry
      await this.db.query(
        `UPDATE webhook_events SET status = 'failed', error = $2 WHERE id = $1`,
        [event.id, (error as Error).message]
      );

      // Queue to dead letter / retry
      await this.queue.add('webhook-retry', {
        event,
        attempt: 1,
        maxAttempts: 3,
      }, {
        delay: 60_000,  // Retry after 1 minute
        backoff: { type: 'exponential', delay: 60_000 },
      });

      await this.redis.del(idempotencyKey); // Allow retry
      throw error;
    }
  }

  private async routeEvent(event: WebhookEvent): Promise<void> {
    const handlers: Record<string, (payload: any) => Promise<void>> = {
      // Order events
      'order.created': this.handleOrderCreated.bind(this),
      'orders/create': this.handleOrderCreated.bind(this), // Shopify topic format
      'order.updated': this.handleOrderUpdated.bind(this),
      'orders/updated': this.handleOrderUpdated.bind(this),
      'order.cancelled': this.handleOrderCancelled.bind(this),
      'orders/cancelled': this.handleOrderCancelled.bind(this),

      // Product events
      'product.updated': this.handleProductUpdated.bind(this),
      'products/update': this.handleProductUpdated.bind(this),

      // Fulfillment events
      'fulfillment.created': this.handleFulfillmentCreated.bind(this),
      'fulfillments/create': this.handleFulfillmentCreated.bind(this),
    };

    const handler = handlers[event.topic];
    if (handler) {
      await handler(event.payload);
    } else {
      console.warn(`No handler for webhook topic: ${event.topic}`);
    }
  }

  private async handleOrderCreated(payload: any): Promise<void> {
    // 1. Store order in local database
    const order = this.normalizeOrder(payload);
    await this.db.query(
      `INSERT INTO orders (id, external_id, platform, status, total, currency, customer_email, line_items, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (external_id, platform) DO UPDATE SET status = $4, updated_at = NOW()`,
      [order.id, order.externalId, order.platform, order.status, order.total,
       order.currency, order.customerEmail, JSON.stringify(order.lineItems), order.createdAt]
    );

    // 2. Confirm inventory reservation
    await this.inventoryManager.confirmReservation(order.id);

    // 3. Send order confirmation email (see email-universal skill)
    await this.queue.add('send-email', {
      template: 'order-confirmation',
      to: order.customerEmail,
      data: order,
    });

    // 4. Update analytics
    await this.queue.add('track-conversion', {
      orderId: order.id,
      total: order.total,
      items: order.lineItems,
    });
  }

  private async handleOrderUpdated(payload: any): Promise<void> {
    const order = this.normalizeOrder(payload);
    await this.db.query(
      `UPDATE orders SET status = $1, updated_at = NOW() WHERE external_id = $2 AND platform = $3`,
      [order.status, order.externalId, order.platform]
    );
  }

  private async handleOrderCancelled(payload: any): Promise<void> {
    const order = this.normalizeOrder(payload);

    // Release inventory
    await this.inventoryManager.releaseReservation(order.id);

    // Update order status
    await this.db.query(
      `UPDATE orders SET status = 'cancelled', updated_at = NOW() WHERE external_id = $1`,
      [order.externalId]
    );

    // Trigger refund if paid (see payment-processing-universal skill)
    if (order.paymentStatus === 'paid') {
      await this.queue.add('process-refund', { orderId: order.id });
    }
  }

  private async handleProductUpdated(payload: any): Promise<void> {
    // Invalidate caches
    const handle = payload.handle || payload.slug;
    await this.redis.del(`product:${handle}`);

    // Re-index for search (see search-universal skill)
    await this.queue.add('reindex-product', { productId: payload.id });
  }

  private async handleFulfillmentCreated(payload: any): Promise<void> {
    // Send shipping notification
    await this.queue.add('send-email', {
      template: 'shipping-confirmation',
      to: payload.email || payload.destination?.email,
      data: {
        trackingNumber: payload.tracking_number,
        trackingUrl: payload.tracking_url || payload.tracking_urls?.[0],
        carrier: payload.tracking_company,
      },
    });
  }

  private normalizeOrder(payload: any): NormalizedOrder {
    // Normalize between Shopify and WooCommerce order formats
    // Implementation depends on source platform
    // ...
  }
}
```

---

## Shipping & Tax Calculation

### Shipping Rate Calculation

```typescript
// --- Shipping Rate Provider ---
interface ShippingRate {
  id: string;
  carrier: string;        // "ups", "fedex", "usps", "dhl"
  service: string;         // "ground", "express", "overnight"
  name: string;            // "UPS Ground (5-7 business days)"
  price: Money;
  estimatedDays: { min: number; max: number };
  trackingAvailable: boolean;
}

interface ShippingAddress {
  address1: string;
  address2?: string;
  city: string;
  province: string;       // State/province code
  postalCode: string;
  country: string;        // ISO 3166-1 alpha-2
}

interface ShippingRequest {
  origin: ShippingAddress;
  destination: ShippingAddress;
  items: Array<{
    weight: { value: number; unit: 'kg' | 'lb' | 'g' | 'oz' };
    dimensions?: { length: number; width: number; height: number; unit: 'cm' | 'in' };
    quantity: number;
    price: Money;
  }>;
}

// Multi-carrier shipping calculator
class ShippingCalculator {
  /**
   * Calculate rates from multiple carriers and return sorted by price.
   */
  async getRates(request: ShippingRequest): Promise<ShippingRate[]> {
    // Free shipping threshold
    const orderTotal = request.items.reduce(
      (sum, item) => sum + item.price.amount * item.quantity, 0
    );

    const rates: ShippingRate[] = [];

    // Free shipping over threshold
    const FREE_SHIPPING_THRESHOLD = 7500; // $75.00 in cents
    if (orderTotal >= FREE_SHIPPING_THRESHOLD) {
      rates.push({
        id: 'free-standard',
        carrier: 'internal',
        service: 'standard',
        name: 'Free Standard Shipping (5-7 business days)',
        price: { amount: 0, currencyCode: 'USD' },
        estimatedDays: { min: 5, max: 7 },
        trackingAvailable: true,
      });
    }

    // Flat rate options (simplest approach)
    const totalWeight = request.items.reduce((sum, item) => {
      const weightLbs = convertToLbs(item.weight);
      return sum + weightLbs * item.quantity;
    }, 0);

    rates.push(
      {
        id: 'standard',
        carrier: 'usps',
        service: 'ground',
        name: 'Standard Shipping (5-7 business days)',
        price: { amount: calculateFlatRate(totalWeight, 'standard'), currencyCode: 'USD' },
        estimatedDays: { min: 5, max: 7 },
        trackingAvailable: true,
      },
      {
        id: 'express',
        carrier: 'ups',
        service: 'express',
        name: 'Express Shipping (2-3 business days)',
        price: { amount: calculateFlatRate(totalWeight, 'express'), currencyCode: 'USD' },
        estimatedDays: { min: 2, max: 3 },
        trackingAvailable: true,
      },
      {
        id: 'overnight',
        carrier: 'fedex',
        service: 'overnight',
        name: 'Overnight Shipping (1 business day)',
        price: { amount: calculateFlatRate(totalWeight, 'overnight'), currencyCode: 'USD' },
        estimatedDays: { min: 1, max: 1 },
        trackingAvailable: true,
      }
    );

    // Sort by price ascending
    return rates.sort((a, b) => a.price.amount - b.price.amount);
  }
}

function calculateFlatRate(
  weightLbs: number,
  service: 'standard' | 'express' | 'overnight'
): number {
  // Flat rate tiers (in cents)
  const tiers: Record<string, Array<{ maxWeight: number; price: number }>> = {
    standard: [
      { maxWeight: 1, price: 499 },
      { maxWeight: 5, price: 799 },
      { maxWeight: 20, price: 1299 },
      { maxWeight: Infinity, price: 1999 },
    ],
    express: [
      { maxWeight: 1, price: 999 },
      { maxWeight: 5, price: 1499 },
      { maxWeight: 20, price: 2499 },
      { maxWeight: Infinity, price: 3999 },
    ],
    overnight: [
      { maxWeight: 1, price: 1999 },
      { maxWeight: 5, price: 2999 },
      { maxWeight: 20, price: 4999 },
      { maxWeight: Infinity, price: 7999 },
    ],
  };

  const tier = tiers[service].find(t => weightLbs <= t.maxWeight);
  return tier?.price ?? 1999;
}

function convertToLbs(weight: { value: number; unit: string }): number {
  const conversions: Record<string, number> = {
    lb: 1,
    kg: 2.20462,
    g: 0.00220462,
    oz: 0.0625,
  };
  return weight.value * (conversions[weight.unit] || 1);
}
```

### Tax Calculation

```typescript
// --- Tax Calculation ---
// For production, use a tax API (TaxJar, Avalara, Stripe Tax)
// Manual calculation shown here for simple cases

interface TaxResult {
  taxableAmount: Money;
  taxAmount: Money;
  rate: number;               // e.g. 0.0875 for 8.75%
  breakdown: TaxBreakdown[];
}

interface TaxBreakdown {
  jurisdiction: string;       // "California", "Los Angeles County", "LA City"
  type: 'state' | 'county' | 'city' | 'special';
  rate: number;
  amount: Money;
}

// Simple US sales tax (for MVP -- use TaxJar/Avalara in production)
const US_STATE_TAX_RATES: Record<string, number> = {
  CA: 0.0725, TX: 0.0625, NY: 0.04, FL: 0.06,
  WA: 0.065, IL: 0.0625, PA: 0.06, OH: 0.0575,
  GA: 0.04, NC: 0.0475, NJ: 0.06625, VA: 0.053,
  // ... add more states
  OR: 0, MT: 0, DE: 0, NH: 0, AK: 0, // No sales tax
};

function calculateSimpleTax(
  subtotal: Money,
  shippingAddress: ShippingAddress,
  taxableShipping = false,
  shippingCost?: Money
): TaxResult {
  const stateRate = US_STATE_TAX_RATES[shippingAddress.province] || 0;

  if (stateRate === 0) {
    return {
      taxableAmount: subtotal,
      taxAmount: { amount: 0, currencyCode: subtotal.currencyCode },
      rate: 0,
      breakdown: [],
    };
  }

  let taxableAmount = subtotal.amount;
  if (taxableShipping && shippingCost) {
    taxableAmount += shippingCost.amount;
  }

  const taxAmount = Math.round(taxableAmount * stateRate);

  return {
    taxableAmount: { amount: taxableAmount, currencyCode: subtotal.currencyCode },
    taxAmount: { amount: taxAmount, currencyCode: subtotal.currencyCode },
    rate: stateRate,
    breakdown: [
      {
        jurisdiction: shippingAddress.province,
        type: 'state',
        rate: stateRate,
        amount: { amount: taxAmount, currencyCode: subtotal.currencyCode },
      },
    ],
  };
}

// Production tax calculation via TaxJar API
async function calculateTaxWithTaxJar(
  order: {
    toAddress: ShippingAddress;
    fromAddress: ShippingAddress;
    lineItems: Array<{ id: string; quantity: number; unitPrice: number; productTaxCode?: string }>;
    shipping: number;
  }
): Promise<TaxResult> {
  const response = await fetch('https://api.taxjar.com/v2/taxes', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.TAXJAR_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      to_country: order.toAddress.country,
      to_state: order.toAddress.province,
      to_zip: order.toAddress.postalCode,
      to_city: order.toAddress.city,
      from_country: order.fromAddress.country,
      from_state: order.fromAddress.province,
      from_zip: order.fromAddress.postalCode,
      shipping: order.shipping / 100, // TaxJar expects dollars
      line_items: order.lineItems.map(item => ({
        id: item.id,
        quantity: item.quantity,
        unit_price: item.unitPrice / 100,
        product_tax_code: item.productTaxCode,
      })),
    }),
  });

  const data = await response.json();
  const tax = data.tax;

  return {
    taxableAmount: { amount: Math.round(tax.taxable_amount * 100), currencyCode: 'USD' },
    taxAmount: { amount: Math.round(tax.amount_to_collect * 100), currencyCode: 'USD' },
    rate: tax.rate,
    breakdown: (tax.breakdown?.line_items || []).map((item: any) => ({
      jurisdiction: item.state || 'combined',
      type: 'state',
      rate: item.combined_tax_rate,
      amount: { amount: Math.round(item.tax_collectable * 100), currencyCode: 'USD' },
    })),
  };
}
```

```python
# Python: Tax calculation with TaxJar
import os
import httpx

TAXJAR_API_KEY = os.environ["TAXJAR_API_KEY"]

async def calculate_tax(
    to_address: dict,
    from_address: dict,
    line_items: list[dict],
    shipping_cents: int,
) -> dict:
    """Calculate sales tax using TaxJar API."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.taxjar.com/v2/taxes",
            headers={"Authorization": f"Bearer {TAXJAR_API_KEY}"},
            json={
                "to_country": to_address["country"],
                "to_state": to_address["province"],
                "to_zip": to_address["postal_code"],
                "to_city": to_address["city"],
                "from_country": from_address["country"],
                "from_state": from_address["province"],
                "from_zip": from_address["postal_code"],
                "shipping": shipping_cents / 100,
                "line_items": [
                    {
                        "id": item["id"],
                        "quantity": item["quantity"],
                        "unit_price": item["unit_price_cents"] / 100,
                        "product_tax_code": item.get("tax_code"),
                    }
                    for item in line_items
                ],
            },
        )
        response.raise_for_status()
        tax = response.json()["tax"]

        return {
            "taxable_amount_cents": round(tax["taxable_amount"] * 100),
            "tax_amount_cents": round(tax["amount_to_collect"] * 100),
            "rate": tax["rate"],
        }
```

---

## Testing Guide

### Key Test Scenarios

```typescript
// --- E-Commerce Test Utilities ---

// Mock product data
function createMockProduct(overrides: Partial<Product> = {}): Product {
  return {
    id: 'prod_test_123',
    platform: 'shopify',
    name: 'Test Product',
    slug: 'test-product',
    description: 'A test product for unit tests',
    type: 'simple',
    categories: [{ id: 'cat_1', name: 'Test Category', slug: 'test-category' }],
    tags: ['test'],
    price: { amount: 1999, currencyCode: 'USD' },
    images: [{ id: 'img_1', url: 'https://example.com/test.jpg', altText: 'Test', width: 800, height: 600 }],
    availableForSale: true,
    totalInventory: 50,
    options: [],
    variants: [
      {
        id: 'var_test_1',
        sku: 'TEST-001',
        name: 'Default',
        price: { amount: 1999, currencyCode: 'USD' },
        inventory: 50,
        availableForSale: true,
        options: {},
      },
    ],
    seo: { title: 'Test Product', description: 'Test description' },
    metafields: {},
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

// Test: Price calculation never has floating point errors
describe('Price calculations', () => {
  it('should handle $0.10 + $0.20 correctly', () => {
    const a: Money = { amount: 10, currencyCode: 'USD' };
    const b: Money = { amount: 20, currencyCode: 'USD' };
    const result = addMoney(a, b);
    expect(result.amount).toBe(30); // Not 0.30000000000000004
  });

  it('should reject mismatched currencies', () => {
    const usd: Money = { amount: 100, currencyCode: 'USD' };
    const eur: Money = { amount: 100, currencyCode: 'EUR' };
    expect(() => addMoney(usd, eur)).toThrow('Currency mismatch');
  });

  it('should format prices correctly', () => {
    expect(formatPrice({ amount: 1999, currencyCode: 'USD' })).toBe('$19.99');
    expect(formatPrice({ amount: 1000, currencyCode: 'JPY' })).toBe('\u00A51,000');
  });
});

// Test: Cart operations
describe('Cart reducer', () => {
  it('should add items to empty cart', () => {
    const state = cartReducer(initialCartState, {
      type: 'ADD_ITEM',
      payload: { variantId: 'v1', productId: 'p1', name: 'Test', variantName: 'Default', price: { amount: 1999, currencyCode: 'USD' }, quantity: 1 },
    });
    expect(state.items).toHaveLength(1);
    expect(state.items[0].quantity).toBe(1);
  });

  it('should increment quantity for existing item', () => {
    const stateWith1 = cartReducer(initialCartState, {
      type: 'ADD_ITEM',
      payload: { variantId: 'v1', productId: 'p1', name: 'Test', variantName: 'Default', price: { amount: 1999, currencyCode: 'USD' }, quantity: 1 },
    });
    const stateWith2 = cartReducer(stateWith1, {
      type: 'ADD_ITEM',
      payload: { variantId: 'v1', productId: 'p1', name: 'Test', variantName: 'Default', price: { amount: 1999, currencyCode: 'USD' }, quantity: 1 },
    });
    expect(stateWith2.items).toHaveLength(1);
    expect(stateWith2.items[0].quantity).toBe(2);
  });

  it('should respect maxQuantity', () => {
    const state = cartReducer(initialCartState, {
      type: 'ADD_ITEM',
      payload: { variantId: 'v1', productId: 'p1', name: 'Test', variantName: 'Default', price: { amount: 1999, currencyCode: 'USD' }, quantity: 999, maxQuantity: 5 },
    });
    // maxQuantity only enforced on subsequent adds, not first
    const state2 = cartReducer(state, {
      type: 'ADD_ITEM',
      payload: { variantId: 'v1', productId: 'p1', name: 'Test', variantName: 'Default', price: { amount: 1999, currencyCode: 'USD' }, quantity: 10, maxQuantity: 5 },
    });
    expect(state2.items[0].quantity).toBe(5);
  });
});

// Test: Webhook signature verification
describe('Webhook verification', () => {
  it('should verify valid Shopify webhook', () => {
    const secret = 'test-secret';
    const body = '{"id":123}';
    const signature = crypto.createHmac('sha256', secret).update(body).digest('base64');

    const event: WebhookEvent = {
      id: 'wh_1', source: 'shopify', topic: 'orders/create',
      payload: { id: 123 }, receivedAt: new Date(), signature,
    };

    expect(processor.verifySignature(event, body)).toBe(true);
  });

  it('should reject tampered webhook', () => {
    const event: WebhookEvent = {
      id: 'wh_1', source: 'shopify', topic: 'orders/create',
      payload: { id: 123 }, receivedAt: new Date(), signature: 'invalid',
    };

    expect(processor.verifySignature(event, '{"id":123}')).toBe(false);
  });
});
```

---

## Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| Shopify 401 Unauthorized | Wrong access token or API version | Check `X-Shopify-Storefront-Access-Token` header; verify token in Shopify Admin > Apps |
| WooCommerce 401 | Wrong keys or HTTP (not HTTPS) | Consumer key/secret require HTTPS; use OAuth 1.0a for HTTP |
| Floating point price errors | Using `float` for currency | Always store as integer cents; parse with `Math.round(parseFloat(x) * 100)` |
| Duplicate orders | Missing idempotency | Use `idempotencyKey` on checkout mutations; deduplicate webhooks by event ID |
| Overselling | No inventory reservation | Implement reservation pattern with TTL (see Inventory Management section) |
| Stale product data | Missing cache invalidation | Set up product update webhooks to invalidate cache (see Caching section) |
| Checkout redirect fails | Wrong Storefront API scope | Verify `unauthenticated_read_checkouts` and `unauthenticated_write_checkouts` scopes |
| Webhook delivery failures | Timeout on handler | Respond 200 immediately and process async via job queue |
| Cart merging issues | Anonymous vs authenticated carts | Merge cart on login: combine items, prefer authenticated user's cart ID |
| Tax miscalculation | Manual tax tables outdated | Use TaxJar/Avalara API; never maintain your own tax rate database |

### Performance Checklist

- [ ] Product images served via CDN with responsive sizes (`srcset`)
- [ ] Product listings use pagination (not "load all")
- [ ] Search uses dedicated service (Algolia/Elasticsearch), not database LIKE queries
- [ ] Cart state persisted in localStorage with platform sync
- [ ] API responses cached with appropriate TTL (products: 5min, cart: 0, orders: 1min)
- [ ] Webhook handlers respond within 5 seconds (offload to background jobs)
- [ ] Product pages use ISR or SSG for sub-second load times
- [ ] Inventory checks at checkout are atomic (Redis or database locks)

---

## Integrates With

| Skill / Module | Integration Point |
|----------------|-------------------|
| **`payment-processing-universal`** skill | Checkout payment capture, refunds, subscription billing for products |
| **`wordpress-patterns`** skill | WooCommerce runs on WordPress -- use for WP REST API auth, plugin management, deployment |
| **`wordpress-publisher`** module | WP REST API client patterns for content pages alongside WooCommerce products |
| **`search-universal`** skill | Algolia/Elasticsearch for product search, autocomplete, faceted filtering |
| **`caching-universal`** skill | Redis/CDN caching for product catalogs, collection pages, API responses |
| **`mobile-subscription`** module | Contrast: in-app purchases use platform billing (Apple/Google), not e-commerce checkout |
| **`unified-api-client`** module | API client patterns for building the BFF/gateway layer in headless commerce |
| **`auth-universal`** skill | Customer authentication, account management, OAuth for third-party integrations |
| **`email-universal`** skill | Order confirmation, shipping notifications, abandoned cart recovery emails |
| **`webhook-universal`** / `background-jobs-universal` skill | Processing order webhooks reliably with retry and dead letter queues |
| **`analytics-universal`** skill | Conversion tracking, product performance, funnel analysis |
| **`seo-geo-aeo`** skill | Product page SEO, structured data (Schema.org), category page optimization |
