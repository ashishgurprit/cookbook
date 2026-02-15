# Schema Markup Templates

Ready-to-use JSON-LD schema templates for common content types.

## Article Schema

```json
{
  "@context": "https://schema.org",
  "@type": "Article",
  "headline": "[Article Title - max 110 characters]",
  "description": "[Meta description - 150-160 characters]",
  "image": "[Featured image URL]",
  "author": {
    "@type": "Person",
    "name": "[Author Name]",
    "url": "[Author profile URL]"
  },
  "publisher": {
    "@type": "Organization",
    "name": "[Site Name]",
    "logo": {
      "@type": "ImageObject",
      "url": "[Logo URL]"
    }
  },
  "datePublished": "[YYYY-MM-DD]",
  "dateModified": "[YYYY-MM-DD]",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "[Page URL]"
  }
}
```

## Blog Posting Schema

```json
{
  "@context": "https://schema.org",
  "@type": "BlogPosting",
  "headline": "[Title]",
  "description": "[Description]",
  "image": "[Image URL]",
  "author": {
    "@type": "Person",
    "name": "[Author]"
  },
  "publisher": {
    "@type": "Organization",
    "name": "[Site Name]",
    "logo": {
      "@type": "ImageObject",
      "url": "[Logo URL]"
    }
  },
  "datePublished": "[YYYY-MM-DD]",
  "dateModified": "[YYYY-MM-DD]",
  "articleSection": "[Category]",
  "keywords": "[keyword1, keyword2, keyword3]",
  "wordCount": [number]
}
```

## Local Business Schema

```json
{
  "@context": "https://schema.org",
  "@type": "LocalBusiness",
  "name": "[Business Name]",
  "image": "[Business Image URL]",
  "url": "[Website URL]",
  "telephone": "[Phone Number]",
  "email": "[Email Address]",
  "address": {
    "@type": "PostalAddress",
    "streetAddress": "[Street Address]",
    "addressLocality": "[City/Suburb]",
    "addressRegion": "[State]",
    "postalCode": "[Postal Code]",
    "addressCountry": "[Country Code]"
  },
  "geo": {
    "@type": "GeoCoordinates",
    "latitude": [latitude],
    "longitude": [longitude]
  },
  "openingHoursSpecification": [
    {
      "@type": "OpeningHoursSpecification",
      "dayOfWeek": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
      "opens": "09:00",
      "closes": "17:00"
    }
  ],
  "priceRange": "$$",
  "areaServed": {
    "@type": "GeoCircle",
    "geoMidpoint": {
      "@type": "GeoCoordinates",
      "latitude": [latitude],
      "longitude": [longitude]
    },
    "geoRadius": "[radius in meters]"
  },
  "sameAs": [
    "[Facebook URL]",
    "[Instagram URL]",
    "[LinkedIn URL]"
  ]
}
```

## Professional Service Schema

```json
{
  "@context": "https://schema.org",
  "@type": "ProfessionalService",
  "name": "[Business Name]",
  "description": "[Business Description]",
  "url": "[Website]",
  "telephone": "[Phone]",
  "address": {
    "@type": "PostalAddress",
    "streetAddress": "[Address]",
    "addressLocality": "[City]",
    "addressRegion": "[State]",
    "postalCode": "[Postal Code]",
    "addressCountry": "[Country]"
  },
  "hasOfferCatalog": {
    "@type": "OfferCatalog",
    "name": "Services",
    "itemListElement": [
      {
        "@type": "Offer",
        "itemOffered": {
          "@type": "Service",
          "name": "[Service 1]",
          "description": "[Service 1 Description]"
        }
      },
      {
        "@type": "Offer",
        "itemOffered": {
          "@type": "Service",
          "name": "[Service 2]",
          "description": "[Service 2 Description]"
        }
      }
    ]
  }
}
```

## FAQ Page Schema

```json
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "[Question 1]?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "[Answer 1]"
      }
    },
    {
      "@type": "Question",
      "name": "[Question 2]?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "[Answer 2]"
      }
    },
    {
      "@type": "Question",
      "name": "[Question 3]?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "[Answer 3]"
      }
    }
  ]
}
```

## How-To Schema

```json
{
  "@context": "https://schema.org",
  "@type": "HowTo",
  "name": "[How to Title]",
  "description": "[Brief description of what this teaches]",
  "image": "[Image URL]",
  "totalTime": "PT[X]M",
  "estimatedCost": {
    "@type": "MonetaryAmount",
    "currency": "AUD",
    "value": "[cost or 0 if free]"
  },
  "step": [
    {
      "@type": "HowToStep",
      "name": "[Step 1 Name]",
      "text": "[Step 1 detailed instructions]",
      "image": "[Step 1 image URL]"
    },
    {
      "@type": "HowToStep",
      "name": "[Step 2 Name]",
      "text": "[Step 2 detailed instructions]"
    },
    {
      "@type": "HowToStep",
      "name": "[Step 3 Name]",
      "text": "[Step 3 detailed instructions]"
    }
  ]
}
```

## Product Schema

```json
{
  "@context": "https://schema.org",
  "@type": "Product",
  "name": "[Product Name]",
  "image": "[Product Image URL]",
  "description": "[Product Description]",
  "brand": {
    "@type": "Brand",
    "name": "[Brand Name]"
  },
  "sku": "[SKU]",
  "offers": {
    "@type": "Offer",
    "url": "[Product URL]",
    "priceCurrency": "AUD",
    "price": "[Price]",
    "availability": "https://schema.org/InStock",
    "seller": {
      "@type": "Organization",
      "name": "[Seller Name]"
    }
  },
  "aggregateRating": {
    "@type": "AggregateRating",
    "ratingValue": "[Rating]",
    "reviewCount": "[Number of Reviews]"
  }
}
```

## Breadcrumb Schema

```json
{
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  "itemListElement": [
    {
      "@type": "ListItem",
      "position": 1,
      "name": "Home",
      "item": "[Homepage URL]"
    },
    {
      "@type": "ListItem",
      "position": 2,
      "name": "[Category Name]",
      "item": "[Category URL]"
    },
    {
      "@type": "ListItem",
      "position": 3,
      "name": "[Page Name]",
      "item": "[Page URL]"
    }
  ]
}
```

## Organization Schema

```json
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "[Organization Name]",
  "url": "[Website URL]",
  "logo": "[Logo URL]",
  "description": "[Organization Description]",
  "foundingDate": "[YYYY]",
  "contactPoint": {
    "@type": "ContactPoint",
    "telephone": "[Phone]",
    "contactType": "customer service",
    "email": "[Email]",
    "availableLanguage": "English"
  },
  "address": {
    "@type": "PostalAddress",
    "streetAddress": "[Address]",
    "addressLocality": "[City]",
    "addressRegion": "[State]",
    "postalCode": "[Postal Code]",
    "addressCountry": "[Country]"
  },
  "sameAs": [
    "[Social Media URL 1]",
    "[Social Media URL 2]",
    "[Social Media URL 3]"
  ]
}
```

## Event Schema

```json
{
  "@context": "https://schema.org",
  "@type": "Event",
  "name": "[Event Name]",
  "description": "[Event Description]",
  "image": "[Event Image URL]",
  "startDate": "[YYYY-MM-DDTHH:MM]",
  "endDate": "[YYYY-MM-DDTHH:MM]",
  "eventStatus": "https://schema.org/EventScheduled",
  "eventAttendanceMode": "https://schema.org/OfflineEventAttendanceMode",
  "location": {
    "@type": "Place",
    "name": "[Venue Name]",
    "address": {
      "@type": "PostalAddress",
      "streetAddress": "[Address]",
      "addressLocality": "[City]",
      "addressRegion": "[State]",
      "postalCode": "[Postal Code]",
      "addressCountry": "[Country]"
    }
  },
  "organizer": {
    "@type": "Organization",
    "name": "[Organizer Name]",
    "url": "[Organizer URL]"
  },
  "offers": {
    "@type": "Offer",
    "url": "[Ticket URL]",
    "price": "[Price]",
    "priceCurrency": "AUD",
    "availability": "https://schema.org/InStock",
    "validFrom": "[YYYY-MM-DD]"
  }
}
```

## Video Schema

```json
{
  "@context": "https://schema.org",
  "@type": "VideoObject",
  "name": "[Video Title]",
  "description": "[Video Description]",
  "thumbnailUrl": "[Thumbnail URL]",
  "uploadDate": "[YYYY-MM-DD]",
  "duration": "PT[X]M[Y]S",
  "contentUrl": "[Video File URL]",
  "embedUrl": "[Embed URL]",
  "publisher": {
    "@type": "Organization",
    "name": "[Publisher Name]",
    "logo": {
      "@type": "ImageObject",
      "url": "[Logo URL]"
    }
  }
}
```

## Combined @graph Schema

For pages needing multiple schemas, use @graph:

```json
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Article",
      "@id": "[URL]#article",
      "headline": "[Title]",
      "author": {"@id": "[URL]#organization"},
      "publisher": {"@id": "[URL]#organization"}
    },
    {
      "@type": "Organization",
      "@id": "[URL]#organization",
      "name": "[Org Name]",
      "url": "[URL]"
    },
    {
      "@type": "BreadcrumbList",
      "@id": "[URL]#breadcrumb",
      "itemListElement": [...]
    }
  ]
}
```

## Validation

Always validate schema markup:
- Google Rich Results Test: https://search.google.com/test/rich-results
- Schema.org Validator: https://validator.schema.org/
- JSON-LD Playground: https://json-ld.org/playground/
