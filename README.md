# Cisco Intersight ServiceNow Webhook Integration

This ServiceNow Scripted REST API endpoint receives webhook notifications from Cisco Intersight and automatically creates incidents in ServiceNow based on Intersight alarm events.

## Features

- **HMAC-SHA256 Signature Verification**: Validates webhook authenticity using HTTP Signatures specification
- **Automatic Incident Creation**: Creates ServiceNow incidents from Intersight alarm events

## Prerequisites

- ServiceNow instance with incident table access
- Cisco Intersight account with webhook configuration capabilities
- Shared secret key for Intersight Webhook HMAC signature verification

## Installation

1. **Create Scripted REST API Resource**:
   - Navigate to **System Web Services > Scripted REST APIs**
   - Create a new API or add this as a resource to an existing API
   - Set the HTTP method to **POST**
   - Copy the code from `servicenow-new` into the script field

2. **Configure Integration User**:
   - Create a dedicated user account (e.g., `abel.tuter` or `integration.user`)
   - Assign appropriate roles for incident creation
   - Update the `INTEGRATION_USER` constant in the script

3. **Configure Shared Secret**:
   - Store your shared secret key securely
   - Update the `secretKey` variable (line 32) or migrate to system property/encrypted table
   - **Important**: The same secret must be configured in Cisco Intersight webhook settings

4. **Note the Endpoint URL**:
   - After saving, note the generated endpoint URL (e.g., `https://yourinstance.service-now.com/api/now/intersight/webhook`)
   - This will be used in Intersight webhook configuration

## Cisco Intersight Configuration

1. **Create Webhook in Intersight**:
   - Navigate to **Settings > Webhooks**
   - Click **Create Webhook**
   - Enter a name (e.g., "ServiceNow Integration")

2. **Configure Webhook Settings**:
   - **URL**: Enter your ServiceNow endpoint URL
   - **Secret Key**: Enter the same secret configured in ServiceNow

3. **Configure Alarm Events**:
   - Select the alarm severities you want to forward (Critical, Warning, Info, etc.)
   - Save the webhook configuration

