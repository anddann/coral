from algorithm import product_remediation
from config import download_path
import logging
logging.basicConfig(level=logging.INFO)
if __name__=='__main__':

    input ={
    "root": {
        "libraryPlatform": "maven",
        "libraryVendor": "org.apache.activemq",
        "libraryName": "activemq-core",
        "version": "5.7.0",
        "extrasList": None,
        "scope": "compile",
        "dependenciesList": [
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.slf4j",
                "libraryName": "slf4j-api",
                "version": "1.6.6",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.apache.geronimo.specs",
                "libraryName": "geronimo-jms_1.1_spec",
                "version": "1.1.1",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.apache.activemq",
                "libraryName": "kahadb",
                "version": "5.7.0",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.apache.activemq.protobuf",
                "libraryName": "activemq-protobuf",
                "version": "1.1",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.fusesource.mqtt-client",
                "libraryName": "mqtt-client",
                "version": "1.3",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": [
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "org.fusesource.hawtdispatch",
                        "libraryName": "hawtdispatch-transport",
                        "version": "1.11",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": [
                            {
                                "libraryPlatform": "maven",
                                "libraryVendor": "org.fusesource.hawtdispatch",
                                "libraryName": "hawtdispatch",
                                "version": "1.11",
                                "extrasList": None,
                                "scope": "compile",
                                "dependenciesList": []
                            }
                        ]
                    },
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "org.fusesource.hawtbuf",
                        "libraryName": "hawtbuf",
                        "version": "1.9",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": []
                    }
                ]
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.apache.geronimo.specs",
                "libraryName": "geronimo-j2ee-management_1.1_spec",
                "version": "1.0.1",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.springframework",
                "libraryName": "spring-context",
                "version": "3.0.7.RELEASE",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": [
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "org.springframework",
                        "libraryName": "spring-aop",
                        "version": "3.0.7.RELEASE",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": [
                            {
                                "libraryPlatform": "maven",
                                "libraryVendor": "aopalliance",
                                "libraryName": "aopalliance",
                                "version": "1.0",
                                "extrasList": None,
                                "scope": "compile",
                                "dependenciesList": []
                            }
                        ]
                    },
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "org.springframework",
                        "libraryName": "spring-beans",
                        "version": "3.0.7.RELEASE",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": []
                    },
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "org.springframework",
                        "libraryName": "spring-core",
                        "version": "3.0.7.RELEASE",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": [
                            {
                                "libraryPlatform": "maven",
                                "libraryVendor": "commons-logging",
                                "libraryName": "commons-logging",
                                "version": "1.1.1",
                                "extrasList": None,
                                "scope": "compile",
                                "dependenciesList": []
                            }
                        ]
                    },
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "org.springframework",
                        "libraryName": "spring-expression",
                        "version": "3.0.7.RELEASE",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": []
                    },
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "org.springframework",
                        "libraryName": "spring-asm",
                        "version": "3.0.7.RELEASE",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": []
                    }
                ]
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "commons-net",
                "libraryName": "commons-net",
                "version": "3.1",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "org.jasypt",
                "libraryName": "jasypt",
                "version": "1.9.0",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            }
        ]
    }
}

    input ={
    "root": {
        "libraryPlatform": "maven",
        "libraryVendor": "io.netty",
        "libraryName": "netty-codec",
        "version": "4.1.67.Final",
        "extrasList": None,
        "scope": "compile",
        "dependenciesList": [
            {
                "libraryPlatform": "maven",
                "libraryVendor": "io.netty",
                "libraryName": "netty-common",
                "version": "4.1.67.Final",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "io.netty",
                "libraryName": "netty-buffer",
                "version": "4.1.67.Final",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": []
            },
            {
                "libraryPlatform": "maven",
                "libraryVendor": "io.netty",
                "libraryName": "netty-transport",
                "version": "4.1.67.Final",
                "extrasList": None,
                "scope": "compile",
                "dependenciesList": [
                    {
                        "libraryPlatform": "maven",
                        "libraryVendor": "io.netty",
                        "libraryName": "netty-resolver",
                        "version": "4.1.67.Final",
                        "extrasList": None,
                        "scope": "compile",
                        "dependenciesList": []
                    }
                ]
            }
        ]
    }
} 
    product_remediation(graph_api_std_deptree=input, user_clss_file_path=download_path+'netty-codec-4.1.67.Final.jar', project_name='netty-codec')