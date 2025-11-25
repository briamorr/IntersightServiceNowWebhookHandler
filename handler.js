/**
 * Scripted REST API endpoint for Cisco Intersight webhook authentication
 * Validates HMAC-SHA256 signature using HTTP Signatures specification
 * and creates ServiceNow incidents from Intersight alarm events.
 * 
 * Expected Authorization header format:
 * Signature keyId="<key>",algorithm="hmac-sha256",headers="(request-target) host date digest content-type content-length",signature="<base64-signature>"
 * 
 * @param {RESTAPIRequest} request - Incoming HTTP request with Intersight webhook payload
 * @param {RESTAPIResponse} response - HTTP response object
 */
(function process(/*RESTAPIRequest*/ request, /*RESTAPIResponse*/ response) {
    
    // --- CONSTANTS ---
    var LOG_SOURCE = 'IntersightWebhook';
    var CATEGORY_HARDWARE = 'Hardware';
    var STATE_NEW = 1;
    var INTEGRATION_USER = 'john.doe'; // Replace with actual user_name or sys_id
    
    var SEVERITY_CRITICAL = 'critical';
    var SEVERITY_FATAL = 'fatal';
    var SEVERITY_WARNING = 'warning';
    
    var IMPACT_HIGH = 1;
    var URGENCY_HIGH = 1;
    var IMPACT_MEDIUM = 2;
    var URGENCY_MEDIUM = 2;
    var IMPACT_LOW = 3;
    var URGENCY_LOW = 3;
    
    // --- 1. Define Key and Extract Headers ---
    var secretKey = 'secret'; // TODO: store intersight webhook secret in table instead of hardcoded
    var method = 'post';
    var reqTarget = ''; // Initialize variable

    // Extract request target path from URL
    if (request.url) {
        // Regex to capture the path (starting from the first slash after the domain)
        var urlRegex = /^https?:\/\/[^\/]+(\/.*)$/; 
        var pathMatch = request.url.match(urlRegex);

        if (pathMatch && pathMatch.length > 1) {
            reqTarget = pathMatch[1]; 
        }

        gs.info('Resolved Request Target: ' + reqTarget, LOG_SOURCE);
    }

    var gsu = new GlideStringUtil();
    var mac = new GlideCertificateEncryption();
    
    // Extract and validate required headers
    var host = request.getHeader('host');
    var date = request.getHeader('date');
    var digest = request.getHeader('digest');
    var contentType = request.getHeader('content-type');
    var contentLength = request.getHeader('content-length');
    
    // Validate all required headers are present
    if (!host || !date || !digest || !contentType || !contentLength) {
        gs.error('Required headers missing. host: ' + !!host + ', date: ' + !!date + 
                 ', digest: ' + !!digest + ', content-type: ' + !!contentType + 
                 ', content-length: ' + !!contentLength, LOG_SOURCE);
        response.setStatus(400);
        response.setBody({ error: 'Required headers missing for signature verification' });
        return;
    }
    
    // Extract and validate Authorization header
    var authorizationHeader = request.getHeader('authorization');
    if (!authorizationHeader) {
        gs.error('Authorization header missing', LOG_SOURCE);
        response.setStatus(401);
        response.setBody({ error: 'Authorization header is required' });
        return;
    }
    
    var receivedSignature = '';

    // Parse signature from Authorization header (HTTP Signatures format)
    var sigMatch = authorizationHeader.match(/signature="([^"]+)"/);
    if (sigMatch && sigMatch.length > 1) {
        receivedSignature = sigMatch[1];
    } else {
        gs.error('Authorization header missing signature value', LOG_SOURCE);
        response.setStatus(400);
        response.setBody({ error: 'Authorization header missing signature value' });
        return;
    }

    // --- 2. Construct Canonical Message (String to Sign) ---
    // Must match the exact format used by the sender (order matters)
    var canonicalMessage = 
        "(request-target): " + method + " " + reqTarget + "\n" +
        "host: " + host + "\n" +
        "date: " + date + "\n" +
        "digest: " + digest + "\n" +
        "content-type: " + contentType + "\n" +
        "content-length: " + contentLength;

    gs.info('Canonical Message constructed for signing:\n' + canonicalMessage, LOG_SOURCE);

    // --- 3. Calculate HMAC Signature ---
    // Base64 encode the secret key (proven to work with Intersight)
    var encodedKey = gsu.base64Encode(secretKey); 

    var expectedSignature = mac.generateMac(
        encodedKey, 
        "HmacSHA256", 
        canonicalMessage
    );

    // --- 4. Verification Logic ---
    var verificationResult = (expectedSignature === receivedSignature);

    if (verificationResult) {
        gs.info('Signature Verification SUCCESS. Calculated: ' + expectedSignature, LOG_SOURCE);
        response.setStatus(200);

        try {
            // Validate request body exists
            if (!request.body || !request.body.data) {
                var bodyErrorMsg = 'Request body or body.data is missing';
                gs.error(bodyErrorMsg, LOG_SOURCE);
                response.setStatus(400);
                response.setBody({ error: bodyErrorMsg });
                return;
            }

            var requestBody = request.body.data;
            var event = requestBody.Event; 
            
            // --- 1. VALIDATION CHECK ---
            var requiredFields = ['Severity', 'Description'];
            var missingFields = [];
            
            // Ensure the Event object itself exists
            if (!event) {
                var errorMsg = "Intersight Webhook: 'Event' object missing from payload. Skipping incident creation.";
                gs.warn(errorMsg, LOG_SOURCE);
                
                response.setStatus(200); 
                response.setBody({ status: "Acknowledged", message: errorMsg });
                return;
            }

            // Check for required fields in Event object
            requiredFields.forEach(function(field) {
                if (!event[field]) {
                    missingFields.push(field);
                }
            });
            
            if (missingFields.length > 0) {
                var skipMsg = 'Required fields missing in Event payload (' + missingFields.join(', ') + '). Incident not created, but request acknowledged.';
                gs.warn(skipMsg, LOG_SOURCE);
                
                response.setStatus(200); 
                response.setBody({
                    status: "Acknowledged",
                    message: skipMsg
                });
                return;
            }
            
            // --- 2. CREATE INCIDENT ---
            var incidentResult = createIncidentFromEvent(event, requestBody);
            
            if (incidentResult.success) {
                response.setStatus(201); // 201 Created
                response.setBody({
                    message: "Incident created successfully",
                    sys_id: incidentResult.sys_id,
                    incident_number: incidentResult.incident_number
                });
            } else {
                response.setStatus(500);
                response.setBody({ error: incidentResult.error });
            }

        } catch (ex) {
            // Handle unexpected runtime errors
            var error_message = "Error processing webhook: " + ex.getMessage();
            gs.error(error_message, LOG_SOURCE);
            response.setStatus(500);
            response.setBody({ error: error_message });
        }

    } else {
        gs.error('Signature Verification FAILED. Calculated: ' + expectedSignature + ', Received: ' + receivedSignature, LOG_SOURCE);
        response.setStatus(401);
        response.setBody({ error: 'Signature verification failed' });
    }

    /**
     * Creates a ServiceNow incident from an Intersight event
     * @param {Object} event - The Event object from Intersight webhook payload
     * @param {Object} requestBody - The full request body for additional context
     * @returns {Object} Result object with success flag and incident details or error message
     */
    function createIncidentFromEvent(event, requestBody) {
        try {
            var gr = new GlideRecord('incident');
            gr.initialize();
            
            // Set the Short Description
            gr.short_description = 'Intersight Alarm: ' + event.Description;
            
            // --- DYNAMIC PRIORITY MAPPING ---
            var severity = event.Severity.toLowerCase();
            
            if (severity === SEVERITY_CRITICAL || severity === SEVERITY_FATAL) {
                gr.impact = IMPACT_HIGH;
                gr.urgency = URGENCY_HIGH;
            } else if (severity === SEVERITY_WARNING) {
                gr.impact = IMPACT_MEDIUM;
                gr.urgency = URGENCY_MEDIUM;
            } else {
                // Log unexpected severity values
                if (severity !== 'info' && severity !== 'cleared') {
                    gs.warn('Unknown severity value: ' + severity + ', defaulting to Low priority', LOG_SOURCE);
                }
                gr.impact = IMPACT_LOW;
                gr.urgency = URGENCY_LOW;
            }
            
            // --- SET STANDARD FIELDS ---
            gr.category = CATEGORY_HARDWARE; 
            gr.state = STATE_NEW;
            
            // Validate and set caller_id
            var caller = new GlideRecord('sys_user');
            if (caller.get('user_name', INTEGRATION_USER)) {
                gr.caller_id = caller.sys_id;
            } else {
                gs.warn('Integration user "' + INTEGRATION_USER + '" not found, incident will have no caller', LOG_SOURCE);
            }
            
            // --- BUILD COMMENTS/WORK NOTES ---
            gr.comments = buildIncidentComments(event, requestBody);
            
            // Insert the new incident record
            var sysId = gr.insert();
            
            if (!sysId) {
                throw new Error('Failed to insert incident record');
            }
            
            gs.info('Incident created successfully. Number: ' + gr.number + ', sys_id: ' + sysId, LOG_SOURCE);
            
            return {
                success: true,
                sys_id: sysId,
                incident_number: gr.number
            };
            
        } catch (ex) {
            var errorMsg = "Error creating incident: " + ex.getMessage();
            gs.error(errorMsg, LOG_SOURCE);
            return {
                success: false,
                error: errorMsg
            };
        }
    }
    
    /**
     * Builds formatted comments for the incident with Intersight alarm details
     * @param {Object} event - The Event object from Intersight
     * @param {Object} requestBody - The full request body
     * @returns {String} Formatted comments string
     */
    function buildIncidentComments(event, requestBody) {
        var comments = [];
        comments.push('--- Intersight Webhook Details ---');
        comments.push('**Alarm Status:** ' + event.Severity); 
        comments.push('**Affected Object:** ' + (event.AffectedMoDisplayName || 'N/A') + 
                     ' (' + (event.AffectedMoType || 'N/A') + ')');
        comments.push('**Alarm Code:** ' + (event.Code || 'N/A'));
        comments.push('**Creation Time (Intersight):** ' + (event.CreationTime || 'N/A'));
        comments.push('**Last Transition Time:** ' + (event.LastTransitionTime || 'N/A'));

        // Add acknowledgment information if present
        if (event.Acknowledge && event.Acknowledge !== 'None') {
            comments.push('\n**Acknowledge Status:** ' + event.Acknowledge + 
                         ' by ' + (event.AcknowledgeBy || 'N/A') + 
                         ' at ' + (event.AcknowledgeTime || 'N/A'));
        }

        // Add ancestor/hierarchy information if available
        if (event.Ancestors && Array.isArray(event.Ancestors) && event.Ancestors.length > 0) {
            comments.push('\n**Affected System Ancestry:**');
            event.Ancestors.forEach(function(ancestor) {
                comments.push(' - ' + (ancestor.ObjectType || 'N/A') + 
                             ': ' + (ancestor.DisplayProperty || 'N/A'));
            });
        }
        
        // Add additional contextual metadata
        comments.push('\n**Other Contextual Data:**');
        comments.push(' - Event Moid: ' + (event.Moid || 'N/A'));
        comments.push(' - Ancestor MoId: ' + (event.AncestorMoId || 'N/A'));
        comments.push(' - Webhook Operation: ' + (requestBody.Operation || 'N/A'));
        
        return comments.join('\n');
    }

})(request, response);
