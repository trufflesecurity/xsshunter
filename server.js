'use strict';

const get_app_server = require('./app.js');
const get_api_server = require('./api.js');

const database = require('./database.js');
const database_init = database.database_init;

if(!process.env.SSL_CONTACT_EMAIL) {
    console.error(`[ERROR] The environment variable 'SSL_CONTACT_EMAIL' is not set, please set it.`);
    process.exit();
}

(async () => {
	// Ensure database is initialized.
	await database_init();

	const app = await get_app_server();
	const port = process.env.PORT;
	app.listen(port, () => {
		console.log(`XSS Hunter listening on port ${port}`)
	});

	/*
		Enabling the web control panel is 100% optional. This can be
		enabled with the "CONTROL_PANEL_ENABLED" environment variable.

		However, if the user just wants alerts on payload firing then
		they can disable the web control panel to reduce attack surface.
	*/
	if(process.env.CONTROL_PANEL_ENABLED === 'true') {
		// Enable API and static asset serving.
		const api = await get_api_server();
		const port = process.env.API_PORT;
		api.listen(port, () => {
			console.log(`XSS Hunter Control Panel listening on port ${port}`)
		});
	} else {
		console.log(`[INFO] Control panel NOT enabled. Not serving API or GUI server, only acting as a notification server...`);
	}
})();
