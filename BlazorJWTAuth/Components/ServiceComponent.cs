using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using RestSharp;
using RestSharp.Serializers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BlazorJWTAuth.Components
{
    public interface IServiceComponent
    {
        IRestResponse ResponseJson(string url, object requestBody, Dictionary<string, string> requestHeader, List<Parameter> requestParameter, Method method);
        IRestResponse ResponseJsonAuth(string url, object requestBody, Dictionary<string, string> requestHeader, Method method);
    }

    public class ServiceComponent : IServiceComponent
    {
        public IRestResponse ResponseJson(string url, object requestBody, Dictionary<string, string> requestHeader, List<Parameter> requestParameter, Method method)
        {
            var client = new RestClient(url);
            var request = new RestRequest(method)
            {
                RequestFormat = DataFormat.Json,
                JsonSerializer = new CamelCaseSerializer()
            };

            if(requestHeader != null)
            {
                foreach(var item in requestHeader)
                {
                    request.AddHeader(item.Key, item.Value);
                }
            }

            if(requestParameter != null)
            {
                foreach(var item in requestParameter)
                {
                    request.AddParameter(item);
                }
            }

            if(requestBody != null)
            {
                request.AddJsonBody(requestBody);
            }

            IRestResponse response = client.Execute(request);
            
            return response;
        }

        public IRestResponse ResponseJsonAuth(string url, object requestBody, Dictionary<string, string> requestHeader, Method method)
        {
            var client = new RestClient(url);
            var request = new RestRequest(method)
            {
                RequestFormat = DataFormat.Json,
                JsonSerializer = new CamelCaseSerializer()
            };

            if (requestHeader != null)
            {
                foreach (var item in requestHeader)
                {
                    request.AddHeader(item.Key, item.Value);
                }
            }            

            if (requestBody != null)
            {
                request.AddJsonBody(requestBody);
            }

            IRestResponse response = client.Execute(request);

            return response;
        }

        public class CamelCaseSerializer : ISerializer
        {
            public string ContentType { get; set; }
            public CamelCaseSerializer()
            {
                ContentType = "application/json";
            }

            public string Serialize(object obj)
            {
                var camelCaseSetting = new JsonSerializerSettings()
                {
                    ContractResolver = new CamelCasePropertyNamesContractResolver()
                };

                string json = JsonConvert.SerializeObject(obj, camelCaseSetting);
                return json;
            }
        }
    }
}
