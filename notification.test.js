const notification = require('./notification');
 
test('send an email notification', () => {
    const email = "dustin@trufflesec.com"

    var payload_fire_data = {
        id: 1,
        user_id: 2,
        url: "http://google.com",
        ip_address: "127.0.0.1",
        referer: "http://google.com",
        user_agent: "TruffleHog",
        cookies: [],
        title: "Hello",
        secrets: {},
        origin: "http://google.com",
        screenshot_id: 1,
        was_iframe: true,
        browser_timestamp: 1,
        correlated_request: 'No correlated request found for this injection.',
    }

    notification.send_email_notification(payload_fire_data, email);

  });