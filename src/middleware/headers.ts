// "use strict";
import { IncomingHttpHeaders } from 'http';

import { hostname } from 'os';
import { error } from 'winston';
import { uniq } from 'lodash';
import { Request, Response } from 'express';
import meta from '../meta';
import languages from '../languages';
import helpers from '../helpers';
import plugins from '../plugins';

type Middleware = {
    addHeaders : string,
    autoLocale : string
}
type Next = (fruit: string) => string;


export default function (middleware : Middleware) {
    middleware.addHeaders = helpers.try((req : Request, res : Response, next : Next) => {
        const headers:IncomingHttpHeaders = {
            'X-Powered-By': encodeURI(meta.config['powered-by'] || 'NodeBB'),
            'Access-Control-Allow-Methods': encodeURI(meta.config['access-control-allow-methods'] || ''),
            'Access-Control-Allow-Headers': encodeURI(meta.config['access-control-allow-headers'] || ''),
        };

        if (meta.config['csp-frame-ancestors']) {
            headers['Content-Security-Policy'] = `frame-ancestors ${meta.config['csp-frame-ancestors']}`;
            if (meta.config['csp-frame-ancestors'] === '\'none\'') {
                headers['X-Frame-Options'] = 'DENY';
            }
        } else {
            headers['Content-Security-Policy'] = 'frame-ancestors \'self\'';
            headers['X-Frame-Options'] = 'SAMEORIGIN';
        }

        if (meta.config['access-control-allow-origin']) {
            let origins = meta.config['access-control-allow-origin'].split(',');
            origins = origins.map((origin: string) => origin && origin.trim());
            
            if (origins.includes(req.get('origin'))) {
                headers['Access-Control-Allow-Origin'] = encodeURI(req.get('origin'));
                headers.Vary = headers.Vary ? `${headers.Vary}, Origin` : 'Origin';
            }
        }

        if (meta.config['access-control-allow-origin-regex']) {
            let originsRegex = meta.config['access-control-allow-origin-regex'].split(',');
            originsRegex = originsRegex.map((origin: string) => {
                try {
                    let val : string = <string> <unknown>(new RegExp(origin.trim()));
                    origin = val;
                } catch (err) {
                    error(`[middleware.addHeaders] Invalid RegExp For access-control-allow-origin ${origin}`);
                    origin = null;
                }
                return origin;
            });

            originsRegex.forEach((regex: { test: (arg0: string) => any; }) => {
                if (regex && regex.test(req.get('origin'))) {
                    headers['Access-Control-Allow-Origin'] = encodeURI(req.get('origin'));
                    headers.Vary = headers.Vary ? `${headers.Vary}, Origin` : 'Origin';
                }
            });
        }

        if (meta.config['permissions-policy']) {
            headers['Permissions-Policy'] = meta.config['permissions-policy'];
        }

        if (meta.config['access-control-allow-credentials']) {
            headers['Access-Control-Allow-Credentials'] = meta.config['access-control-allow-credentials'];
        }

        if (process.env.NODE_ENV === 'development') {
            headers['X-Upstream-Hostname'] = hostname();
        }

        for (const [key, value] of Object.entries(headers)) {
            if (value) {
                res.setHeader(key, value);
            }
        }

        next("hi");
    });

    middleware.autoLocale = helpers.try(async (req : Request, res : Response, next : Next) => {
        await plugins.hooks.fire('filter:middleware.autoLocale', {
            req: req,
            res: res,
        });
        if (req.query.lang) {
            const langs = await listCodes();
            if (!langs.includes(req.query.lang)) {
                req.query.lang = meta.config.defaultLang;
            }
            return next("hi");
        }

        if (meta.config.autoDetectLang) {
            const langs = await listCodes();
            const lang = req.acceptsLanguages(langs);
            if (!lang) {
                return next("hi");
            }
            req.query.lang = lang;
        }

        next("hi");
    });

    async function listCodes() {
        const defaultLang = meta.config.defaultLang || 'en-GB';
        try {
            const codes = await languages.listCodes();
            return uniq([defaultLang, ...codes]);
        } catch (err) {
            error(`[middleware/autoLocale] Could not retrieve languages codes list! ${err.stack}`);
            return [defaultLang];
        }
    }
};