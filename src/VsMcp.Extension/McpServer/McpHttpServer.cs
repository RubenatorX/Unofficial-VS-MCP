using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using VsMcp.Shared;
using VsMcp.Shared.Protocol;

namespace VsMcp.Extension.McpServer
{
    /// <summary>
    /// HTTP server that listens on a dynamic localhost port and handles MCP JSON-RPC requests.
    /// Requests must carry the per-session bearer token written to the port file, and browser
    /// requests are only accepted from origins listed in server-settings.json.
    /// </summary>
    public class McpHttpServer : IDisposable
    {
        private readonly McpRequestRouter _router;
        private HttpListener _listener;
        private CancellationTokenSource _cts;
        private int _port;
        private bool _disposed;
        private ServerSecuritySettings _security;
        private string _authToken;

        public int Port => _port;

        public McpHttpServer(McpRequestRouter router)
        {
            _router = router ?? throw new ArgumentNullException(nameof(router));
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _security = ServerSecuritySettings.Load();
            _authToken = ServerSecuritySettings.GenerateToken();

            // Find an available port
            var tempListener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            tempListener.Start();
            _port = ((IPEndPoint)tempListener.LocalEndpoint).Port;
            tempListener.Stop();

            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{_port}/");
            _listener.Start();

            // Write port file for discovery
            var pid = Process.GetCurrentProcess().Id;
            PortDiscovery.WritePort(pid, _port, token: _authToken);

            // Start listening loop (fire-and-forget is intentional)
            _ = Task.Run(() => ListenLoopAsync(_cts.Token));

            Debug.WriteLine($"[VsMcp] HTTP server started on port {_port}");
        }

        public void UpdateSolutionInPortFile(string slnPath)
        {
            var pid = Process.GetCurrentProcess().Id;
            PortDiscovery.UpdateSolutionPath(pid, slnPath);
        }

        public void Stop()
        {
            _cts?.Cancel();
            _listener?.Stop();

            var pid = Process.GetCurrentProcess().Id;
            PortDiscovery.RemovePort(pid);

            Debug.WriteLine("[VsMcp] HTTP server stopped");
        }

        private async Task ListenLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _listener.IsListening)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    // Handle each request on its own task
                    _ = Task.Run(() => HandleRequestAsync(context), ct);
                }
                catch (HttpListenerException) when (ct.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[VsMcp] Listener error: {ex.Message}");
                }
            }
        }

        private async Task HandleRequestAsync(HttpListenerContext context)
        {
            // Origin allowed to read the response (CORS); null means no CORS header is sent.
            string corsOrigin = null;
            try
            {
                var request = context.Request;
                var response = context.Response;

                // http.sys accepts any client that sends "Host: localhost", so also reject
                // connections that do not originate from this machine.
                if (!request.IsLocal)
                {
                    await WriteResponseAsync(response, 403, "{\"error\": \"Remote connections not allowed\"}");
                    return;
                }

                // Browsers always send Origin on cross-origin requests. Reject any origin that
                // is not explicitly allowed so web pages cannot drive Visual Studio.
                var origin = request.Headers["Origin"];
                if (!string.IsNullOrEmpty(origin))
                {
                    if (!_security.IsOriginAllowed(origin))
                    {
                        await WriteResponseAsync(response, 403, "{\"error\": \"Origin not allowed\"}");
                        return;
                    }
                    corsOrigin = origin;
                }

                // CORS preflight for allowed origins
                if (request.HttpMethod == "OPTIONS")
                {
                    if (corsOrigin != null)
                    {
                        response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                        var requestedHeaders = request.Headers["Access-Control-Request-Headers"];
                        if (!string.IsNullOrEmpty(requestedHeaders))
                            response.Headers.Add("Access-Control-Allow-Headers", requestedHeaders);
                        response.Headers.Add("Access-Control-Max-Age", "600");
                    }
                    await WriteResponseAsync(response, 204, "", corsOrigin);
                    return;
                }

                if (_security.RequireAuthToken && !IsAuthorized(request))
                {
                    await WriteResponseAsync(response, 401, "{\"error\": \"Unauthorized\"}", corsOrigin);
                    return;
                }

                // Health check endpoint
                if (request.HttpMethod == "GET" && request.Url.AbsolutePath == "/health")
                {
                    var healthJson = JsonConvert.SerializeObject(new
                    {
                        status = "ok",
                        server = McpConstants.ServerName,
                        version = McpConstants.ServerVersion,
                        port = _port,
                        solutionState = VsMcpPackage.SolutionState
                    });
                    await WriteResponseAsync(response, 200, healthJson, corsOrigin);
                    return;
                }

                // MCP endpoint (POST /mcp)
                if (request.HttpMethod == "POST" && request.Url.AbsolutePath == "/mcp")
                {
                    string body;
                    using (var reader = new StreamReader(request.InputStream, Encoding.UTF8))
                    {
                        body = await reader.ReadToEndAsync();
                    }

                    JsonRpcRequest rpcRequest;
                    try
                    {
                        rpcRequest = JsonConvert.DeserializeObject<JsonRpcRequest>(body);
                    }
                    catch (JsonException ex)
                    {
                        var errorResp = JsonRpcResponse.ErrorResponse(null, McpConstants.ParseError, $"Parse error: {ex.Message}");
                        await WriteResponseAsync(response, 200, JsonConvert.SerializeObject(errorResp), corsOrigin);
                        return;
                    }

                    // 2026-07-28 §Streamable HTTP: if Mcp-Method / Mcp-Name headers are present,
                    // they MUST match the request body. Reject with HeaderMismatchError otherwise.
                    var headerMethod = request.Headers[McpConstants.HeaderMcpMethod];
                    if (!string.IsNullOrEmpty(headerMethod) && !string.Equals(headerMethod, rpcRequest.Method, StringComparison.Ordinal))
                    {
                        var mismatchResp = JsonRpcResponse.ErrorResponse(
                            rpcRequest.Id,
                            McpConstants.HeaderMismatch,
                            $"Mcp-Method header '{headerMethod}' does not match body method '{rpcRequest.Method}'.");
                        await WriteResponseAsync(response, 200, JsonConvert.SerializeObject(mismatchResp), corsOrigin);
                        return;
                    }
                    var headerName = request.Headers[McpConstants.HeaderMcpName];
                    if (!string.IsNullOrEmpty(headerName) && rpcRequest.Method == McpConstants.MethodToolsCall)
                    {
                        var bodyName = rpcRequest.Params?.Value<string>("name");
                        if (!string.IsNullOrEmpty(bodyName) && !string.Equals(headerName, bodyName, StringComparison.Ordinal))
                        {
                            var mismatchResp = JsonRpcResponse.ErrorResponse(
                                rpcRequest.Id,
                                McpConstants.HeaderMismatch,
                                $"Mcp-Name header '{headerName}' does not match tools/call body name '{bodyName}'.");
                            await WriteResponseAsync(response, 200, JsonConvert.SerializeObject(mismatchResp), corsOrigin);
                            return;
                        }
                    }

                    var method = rpcRequest.Method ?? "(null)";
                    McpRequestRouter.Log($"[HTTP] >>> {method} id={rpcRequest.Id} - routing start");

                    var rpcResponse = await _router.RouteAsync(rpcRequest);

                    McpRequestRouter.Log($"[HTTP] <<< {method} id={rpcRequest.Id} - routing done, response={(rpcResponse != null ? "yes" : "null")}");

                    if (rpcResponse == null)
                    {
                        // Notification - no response body needed
                        await WriteResponseAsync(response, 204, "", corsOrigin);
                        return;
                    }

                    var jsonResponse = JsonConvert.SerializeObject(rpcResponse, new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore
                    });
                    McpRequestRouter.Log($"[HTTP] <<< {method} id={rpcRequest.Id} - writing {jsonResponse.Length} bytes");
                    await WriteResponseAsync(response, 200, jsonResponse, corsOrigin);
                    McpRequestRouter.Log($"[HTTP] <<< {method} id={rpcRequest.Id} - write complete");
                    return;
                }

                // 404 for everything else
                await WriteResponseAsync(response, 404, "{\"error\": \"Not found\"}", corsOrigin);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[VsMcp] Request handling error: {ex.Message}");
                try
                {
                    await WriteResponseAsync(context.Response, 500, $"{{\"error\": \"{ex.Message}\"}}", corsOrigin);
                }
                catch { /* best effort */ }
            }
        }

        private bool IsAuthorized(HttpListenerRequest request)
        {
            const string prefix = "Bearer ";
            var header = request.Headers["Authorization"];
            if (string.IsNullOrEmpty(header) || !header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return false;
            return ServerSecuritySettings.TokensEqual(_authToken, header.Substring(prefix.Length).Trim());
        }

        private static async Task WriteResponseAsync(HttpListenerResponse response, int statusCode, string body, string corsOrigin = null)
        {
            response.StatusCode = statusCode;
            response.ContentType = "application/json";
            if (corsOrigin != null)
            {
                response.Headers.Add("Access-Control-Allow-Origin", corsOrigin);
                response.Headers.Add("Vary", "Origin");
            }

            if (!string.IsNullOrEmpty(body))
            {
                var buffer = Encoding.UTF8.GetBytes(body);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            }

            response.Close();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                Stop();
                _cts?.Dispose();
                (_listener as IDisposable)?.Dispose();
            }
        }
    }
}
