import os from 'os';
import winston from 'winston';
import _ from 'lodash';

import meta from '../meta';
import languages from '../languages';
import { tryFunc } from './helpers';
import plugins from '../plugins';

interface Request {
  get: (property: string) => string | undefined
  query: { lang?: string }
  acceptsLanguages: (languages: string[]) => string | false
  uid: number
}

interface Response {
  setHeader: (key: string, value: string) => void
}

interface NextFunction {
  (): void
}

interface Middleware {
  addHeaders: (req: Request, res: Response, next: NextFunction) => void
  autoLocale: (req: Request, res: Response, next: NextFunction) => void | Promise<void>
}

const middleware: Middleware = {
    addHeaders: function (req: Request, res: Response, next: NextFunction): void {
        throw new Error('Function not implemented.');
    },
    autoLocale: function (req: Request, res: Response, next: NextFunction): void | Promise<void> {
        throw new Error('Function not implemented.');
    },
};

middleware.addHeaders = tryFunc((req: Request, res: Response, next: NextFunction) => {
    const headers = {
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
         //   headers.Vary = headers.Vary ? `${headers.Vary}, Origin` : 'Origin';
        }
    }
});


if (meta.config['access-control-allow-origin-regex']) {
let originsRegex = meta.config['access-control-allow-origin-regex'].split(',');
originsRegex = originsRegex.map((origin: string) => {
        try {
            const val : string = <string> <unknown>(new RegExp(origin.trim()));
            origin = val;
        } catch (err) {
            winston.error(`[middleware.addHeaders] Invalid RegExp For access-control-allow-origin ${origin}`);
            origin = null;
        }
         return origin;
    });
}