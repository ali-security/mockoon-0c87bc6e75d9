import { BodyTypes, Environment, ServerErrorCodes } from '@mockoon/commons';
import { expect } from 'chai';
import { promises as fs } from 'fs';
import { get as httpGet } from 'http';
import { resolve as pathResolve } from 'path';
import { MockoonServer } from '../../../src';

const port = 3020;
const relativePathError =
  'Access to relative path outside of the environment base directory';
const absolutePathError =
  'Access to absolute path outside of the original static base directory';
// content of the package.json file located outside of the served directories
const packageNameField = '"name": "@mockoon/commons-server"';

async function getEnvironment(): Promise<Environment> {
  const environmentJson = await fs.readFile(
    './test/data/environments/test-env.json',
    'utf-8'
  );

  return JSON.parse(environmentJson) as Environment;
}

function buildRequest(
  query: Record<string, string> = {},
  params: Record<string, string> = {}
): any {
  return { query, params, body: {} };
}

function callGetSafeFilePath(
  server: MockoonServer,
  filePath: string,
  request?: any
): string {
  return (server as any).getSafeFilePath(filePath, request);
}

function getSafeFilePathError(
  server: MockoonServer,
  filePath: string,
  request?: any
): string {
  try {
    callGetSafeFilePath(server, filePath, request);
  } catch (error: any) {
    return error.message;
  }

  return '';
}

function getBody(path: string): Promise<{ status?: number; body: string }> {
  return new Promise((resolve, reject) => {
    const url = `http://localhost:${port}${path}`;
    const clientRequest = httpGet(url, (response) => {
      let body = '';

      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
      });
      response.on('end', () => {
        resolve({ status: response.statusCode, body });
      });
    });

    clientRequest.on('error', reject);
  });
}

describe('Server file path traversal protection', () => {
  const dataDirectory = pathResolve('./test/data');
  const publicDirectory = pathResolve('./test/data/public');
  let environment: Environment;
  let server: MockoonServer;

  before(async () => {
    environment = await getEnvironment();
    server = new MockoonServer(environment, {
      environmentDirectory: dataDirectory
    });
  });

  describe('Paths without templating', () => {
    it('should allow escaping the environment directory when there is no templating', () => {
      const result = callGetSafeFilePath(server, '../outside.txt');

      expect(result).to.equal(pathResolve(dataDirectory, '../outside.txt'));
    });

    it('should allow an absolute path outside of the environment directory when there is no templating', () => {
      const filePath = pathResolve(dataDirectory, '../../package.json');
      const result = callGetSafeFilePath(server, filePath);

      expect(pathResolve(result)).to.equal(filePath);
    });
  });

  describe('Templated relative paths', () => {
    it('should allow a templated relative path inside the environment directory', () => {
      const filePath = "./{{queryParam 'filename'}}";
      const request = buildRequest({ filename: 'plain.data' });
      const result = callGetSafeFilePath(server, filePath, request);

      expect(result).to.equal(pathResolve(dataDirectory, 'plain.data'));
    });

    it('should block a templated relative path escaping the environment directory', () => {
      const filePath = "./{{queryParam 'filename'}}";
      const request = buildRequest({ filename: '../../package.json' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(relativePathError);
    });

    it('should block a templated relative path escaping the environment directory from a sub folder', () => {
      const filePath = "./static/{{queryParam 'filename'}}";
      const request = buildRequest({ filename: '../../../../etc/passwd' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(relativePathError);
    });

    it('should block a templated relative path escaping to a sibling directory sharing the same prefix', () => {
      const filePath = "./{{queryParam 'filename'}}";
      const request = buildRequest({ filename: '../data-secret/file.txt' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(relativePathError);
    });

    it('should block a fully templated relative path escaping the environment directory', () => {
      const filePath = "{{queryParam 'filename'}}";
      const request = buildRequest({ filename: '../../package.json' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(relativePathError);
    });

    it('should block a templated relative path escaping the environment directory with a route parameter', () => {
      const filePath = "./{{urlParam 'name'}}";
      const request = buildRequest({}, { name: '../../package.json' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(relativePathError);
    });

    it('should handle backslashes in templated values according to the platform', () => {
      const filePath = "./{{queryParam 'filename'}}";
      const request = buildRequest({ filename: '..\\..\\package.json' });

      if (process.platform === 'win32') {
        const errorMessage = getSafeFilePathError(server, filePath, request);

        expect(errorMessage).to.contain(relativePathError);
      } else {
        // backslashes are regular file name characters on POSIX systems
        const expected = pathResolve(dataDirectory, '..\\..\\package.json');
        const result = callGetSafeFilePath(server, filePath, request);

        expect(result).to.equal(expected);
      }
    });

    it('should allow templated relative paths when the helper is in the middle of the file name', () => {
      const filePath = "./static/file{{queryParam 'name'}}.json";
      const request = buildRequest({ name: '1' });
      const result = callGetSafeFilePath(server, filePath, request);

      expect(result).to.equal(pathResolve(dataDirectory, 'static/file1.json'));
    });

    it('should use the current directory as base when no environment directory is provided', () => {
      const cwdServer = new MockoonServer(environment);
      const filePath = "./{{queryParam 'filename'}}";
      const request = buildRequest({ filename: 'test/data/plain.data' });
      const result = callGetSafeFilePath(cwdServer, filePath, request);

      expect(result).to.equal(pathResolve('test/data/plain.data'));
    });

    it('should block escaping the current directory when no environment directory is provided', () => {
      const cwdServer = new MockoonServer(environment);
      const filePath = "./{{queryParam 'filename'}}";
      const request = buildRequest({ filename: '../package.json' });
      const errorMessage = getSafeFilePathError(cwdServer, filePath, request);

      expect(errorMessage).to.contain(relativePathError);
    });
  });

  describe('Templated absolute paths', () => {
    it('should allow a templated absolute path inside its static base directory', () => {
      const filePath = `${publicDirectory}/{{queryParam 'filename'}}`;
      const request = buildRequest({ filename: 'file.txt' });
      const result = callGetSafeFilePath(server, filePath, request);

      expect(result).to.equal(pathResolve(publicDirectory, 'file.txt'));
    });

    it('should block a templated absolute path escaping its static base directory', () => {
      const filePath = `${publicDirectory}/{{queryParam 'filename'}}`;
      const request = buildRequest({ filename: '../../../package.json' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(absolutePathError);
    });

    it('should block a templated absolute path escaping to a sibling directory sharing the same prefix', () => {
      const filePath = `${publicDirectory}/{{queryParam 'filename'}}`;
      const request = buildRequest({ filename: '../public-secret/file.txt' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(absolutePathError);
    });

    it('should block a fully templated path resolving to an absolute path', () => {
      const filePath = "{{queryParam 'filename'}}";
      const absolutePath = pathResolve(dataDirectory, '../../package.json');
      const request = buildRequest({ filename: absolutePath });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(absolutePathError);
    });

    it('should allow an absolute partially templated file path', () => {
      const filePath = `${publicDirectory}\\file{{queryParam 'name'}}.json`;
      const request = buildRequest({ name: '1' });
      const result = callGetSafeFilePath(server, filePath, request);

      expect(result).to.equal(pathResolve(publicDirectory, 'file1.json'));
    });

    it('should block templated paths escaping the static base when the helper is in the middle of the file name', () => {
      const filePath = `${publicDirectory}/file{{queryParam 'name'}}.json`;
      const request = buildRequest({ name: '/../../secret' });
      const errorMessage = getSafeFilePathError(server, filePath, request);

      expect(errorMessage).to.contain(absolutePathError);
    });
  });

  describe('File serving', () => {
    const serverErrors: ServerErrorCodes[] = [];
    let fileServer: MockoonServer;

    before(async () => {
      const fileEnvironment = await getEnvironment();
      const relativeResponse = fileEnvironment.routes[0].responses[0];
      const absoluteResponse = fileEnvironment.routes[1].responses[0];

      fileEnvironment.port = port;
      relativeResponse.bodyType = BodyTypes.FILE;
      relativeResponse.filePath = "./{{queryParam 'filename'}}";
      relativeResponse.sendFileAsBody = true;
      absoluteResponse.bodyType = BodyTypes.FILE;
      absoluteResponse.filePath = `${dataDirectory}/{{queryParam 'filename'}}`;
      absoluteResponse.sendFileAsBody = true;

      // route serving a file named after a route parameter
      const urlParamRoute = {
        ...fileEnvironment.routes[0],
        uuid: 'a3b9c1d2-6e4f-4f8a-9b7c-2d1e0f3a4b5c',
        endpoint: 'files/:filename',
        responses: [
          {
            ...relativeResponse,
            uuid: 'b4c0d2e3-7f5a-4a9b-8c6d-3e2f1a0b5c6d',
            filePath: "./{{urlParam 'filename'}}"
          }
        ]
      };
      fileEnvironment.routes.push(urlParamRoute);
      fileEnvironment.rootChildren.push({
        type: 'route',
        uuid: urlParamRoute.uuid
      });

      fileServer = new MockoonServer(fileEnvironment, {
        environmentDirectory: dataDirectory
      });
      fileServer.on('error', (errorCode) => {
        serverErrors.push(errorCode);
      });

      await new Promise<void>((resolve) => {
        fileServer.on('started', () => resolve());
        fileServer.start();
      });
    });

    after(() => {
      fileServer.stop();
    });

    it('should serve a file with a templated relative path inside the environment directory', async () => {
      const response = await getBody('/test?filename=plain.data');

      expect(response.status).to.equal(200);
      expect(response.body).to.equal('plainTest');
    });

    it('should not serve a file with a templated relative path escaping the environment directory', async () => {
      const filename = encodeURIComponent('../../package.json');
      const response = await getBody(`/test?filename=${filename}`);

      expect(response.body).to.contain('Error while serving the content:');
      expect(response.body).to.contain(relativePathError);
      expect(response.body).not.to.contain(packageNameField);
      expect(serverErrors).to.include(ServerErrorCodes.ROUTE_SERVING_ERROR);
    });

    it('should serve a file with a templated absolute path inside its static base directory', async () => {
      const response = await getBody('/test2?filename=plain.data');

      expect(response.status).to.equal(200);
      expect(response.body).to.equal('plainTest');
    });

    it('should not serve a file with a templated absolute path escaping its static base directory', async () => {
      const filename = encodeURIComponent('../../package.json');
      const response = await getBody(`/test2?filename=${filename}`);

      expect(response.body).to.contain('Error while serving the content:');
      expect(response.body).to.contain(absolutePathError);
      expect(response.body).not.to.contain(packageNameField);
    });

    it('should serve a file with a templated route parameter inside the environment directory', async () => {
      const response = await getBody('/files/plain.data');

      expect(response.status).to.equal(200);
      expect(response.body).to.equal('plainTest');
    });

    it('should not serve a file with an encoded route parameter escaping the environment directory', async () => {
      const response = await getBody('/files/..%2F..%2Fpackage.json');

      expect(response.body).to.contain('Error while serving the content:');
      expect(response.body).to.contain(relativePathError);
      expect(response.body).not.to.contain(packageNameField);
    });

    it('should not serve system files with an encoded route parameter escaping the environment directory', async () => {
      const filename = `${'..%2F'.repeat(16)}etc%2Fpasswd`;
      const response = await getBody(`/files/${filename}`);

      expect(response.body).to.contain(relativePathError);
      expect(response.body).not.to.contain('root:');
    });
  });
});
