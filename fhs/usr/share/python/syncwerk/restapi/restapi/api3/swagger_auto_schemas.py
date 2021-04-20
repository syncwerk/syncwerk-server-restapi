
from drf_yasg.inspectors import SwaggerAutoSchema
from django.template.loader import render_to_string


class XcodeAutoSchema(SwaggerAutoSchema):
    def __init__(self, view, path, method, components, request, overrides):
        super(XcodeAutoSchema, self).__init__(view,
                                              path,
                                              method,
                                              components,
                                              request,
                                              overrides)

    def get_operation(self, operation_keys):
        operation = super(XcodeAutoSchema, self).get_operation(operation_keys)

        # Using django templates to generate the code
        path_params_with_example = self.path.replace("{repo_id}", "bc90a682-dcc5-4bf2-b5a5-e575934c69e8").replace("{format}", "json").replace("{cms_type}", "support").replace("{activation_key}", "8TgORVrOAe4jKr9ZRAAoFqHNVXG1gzfuf4tA").replace("{user_email}", "user@email.com").replace("{user}", "user@email.com").replace("{email}", "user@email.com").replace("{uidb36}", "ubid36string").replace("{token}", "r9ZRAAoFqHNVXG1gzfuf4tAdeTTFEW56rebfWfeWE").replace("{group_id}", "1").replace("{discuss_id}", "1").replace("{size}", "80").replace("{id}", "1").replace("{slug}", "this-is-wiki-slug").replace("{inst_id}", "1").replace("{notification_id}", "1")

        # Parsing request for information
        template_context = {}
        template_context["request_url"] = self.request._request.build_absolute_uri(path_params_with_example)
        template_context["method"] = self.method
        # template_context["request_body"] = self.overrides['request_body']
        template_context["query_params"] = []
        template_context["form_data"]=[]
        template_context["security"]=self.overrides.get('security', None)
        if 'manual_parameters' in self.overrides:
            for param in self.overrides['manual_parameters']:
                if param.in_ == 'query':
                    template_context["query_params"].append({"key": param.name, "example_value": "example value"})
                elif param.in_ == 'formData':
                    template_context["form_data"].append({"key": param.name, "example_value": "example value"})
        
        if len(template_context["form_data"]) > 0:
            template_context["content_type"]="multipart/form-data"
        else:
            template_context["content_type"]="application/json"
        # if self.overrides['request_body'] is None:
        #     print "NOOOO REQUEST BODY"
        # template_context = {
        #     "request_url": self.request._request.build_absolute_uri(self.path),
        #     "method": self.method,
        #     "query": self.request.query_params,
        #     "body_data": self.request.data,
        #     "headers": {
        #         'Content-Type': self.request.META.get('HTTP_CONTENT_TYPE')
        #     },
        #     "meta": self.request.META,
        #     "request": self.request
        # }
        operation.update({
            'x-code-samples': [
                {
                    "lang": "curl",
                    "source": render_to_string('api3/document-request-example/curl.html', template_context)
                },
                {
                    "lang": "python",
                    "source": render_to_string('api3/document-request-example/python.html', template_context)
                },
                {
                    "lang": "php",
                    "source": render_to_string('api3/document-request-example/php.html', template_context)
                },
                {
                    "lang": "java",
                    "source": render_to_string('api3/document-request-example/java.html', template_context)
                },
                {
                    "lang": "c(liburl)",
                    "source": render_to_string('api3/document-request-example/c.html', template_context)
                }
            ]
        })
        return operation
