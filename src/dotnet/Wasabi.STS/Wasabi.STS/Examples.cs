using Amazon.Runtime.CredentialManagement;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Wasabi.STS
{
    internal class Examples
    {
        const string S3_URL = "https://s3.wasabisys.com";
        const string STS_URL = "https://sts.wasabisys.com";
        const string CREDENTIALS_PROFILE = "user";
        const string ROLE_ARN = "arn:aws:iam::100000185324:role/user_role";
        private readonly AmazonSecurityTokenServiceConfig _stsConfig = new AmazonSecurityTokenServiceConfig() { ServiceURL = STS_URL };
        private readonly AmazonS3Config _s3Config = new AmazonS3Config() { ServiceURL = S3_URL };
        private readonly CredentialProfileOptions credentialProfile;

        public Examples()
        {
            var chain = new CredentialProfileStoreChain();
            if (chain.TryGetProfile(CREDENTIALS_PROFILE, out var basicProfile))
            {
                credentialProfile = basicProfile.Options;
            }
            else
            {
                throw new Exception($"Could not load profile '{CREDENTIALS_PROFILE}'");
            }
        }

        internal async Task GetSessionTokenAsync()
        { 
            IAmazonSecurityTokenService stsClient = new AmazonSecurityTokenServiceClient(
                credentialProfile.AccessKey,
                credentialProfile.SecretKey,
                _stsConfig
                );

            var getSessionTokenRequest = new GetSessionTokenRequest() { DurationSeconds = 900 };

            var response = await stsClient.GetSessionTokenAsync(getSessionTokenRequest);

            IAmazonS3 s3Client = new AmazonS3Client(response.Credentials, _s3Config);

            string bucketName = "test-bucket-created-from-sts-credentials-dotnet";

            var createBucketResponse = await s3Client.PutBucketAsync(bucketName);

            Console.WriteLine($"Created bucket {bucketName}");
        }


        internal async Task AssumeRoleAsync()
        {
            IAmazonSecurityTokenService stsClient = new AmazonSecurityTokenServiceClient(
                credentialProfile.AccessKey,
                credentialProfile.SecretKey,
                _stsConfig
                );

            var assumeRoleRequest = new AssumeRoleRequest()
            {
                DurationSeconds = 900,
                RoleArn = ROLE_ARN,
                RoleSessionName = "test-session"
            };
             
            var assumeRoleResponse = await stsClient.AssumeRoleAsync(assumeRoleRequest);

            IAmazonS3 s3Client = new AmazonS3Client(assumeRoleResponse.Credentials, _s3Config);

            string bucketName = "test-bucket-sts";

            ListObjectsRequest request = new ListObjectsRequest() { BucketName = bucketName };

            var listObjectsResponse = await s3Client.ListObjectsAsync(request);

            Console.WriteLine($"Bucket {bucketName} contains {listObjectsResponse.S3Objects.Count} objects!");
        }

        internal async Task AssumeRoleWithPolicyAsync()
        {
            var policy = @"{
                    ""Version"": ""2012-10-17"",
                    ""Statement"": [
                      {
                        ""Effect"": ""Allow"",
                        ""Action"": ""s3:*"",
                        ""Resource"": [""*""]
                      },
                      {
                        ""Effect"": ""Deny"",
                        ""Action"": ""s3:CreateBucket"",
                        ""Resource"": [""*""]
                      }
                    ]
                  }";

            IAmazonSecurityTokenService stsClient = new AmazonSecurityTokenServiceClient(
                credentialProfile.AccessKey,
                credentialProfile.SecretKey,
                _stsConfig
                );

            var assumeRoleRequest = new AssumeRoleRequest()
            {
                DurationSeconds = 900,
                RoleArn = ROLE_ARN,
                RoleSessionName = "test-session",
                Policy = policy
            };

            var assumeRoleResponse = await stsClient.AssumeRoleAsync(assumeRoleRequest);

            IAmazonS3 s3Client = new AmazonS3Client(assumeRoleResponse.Credentials, _s3Config);

            string bucketName = "test-bucket-sts";

            ListObjectsRequest request = new ListObjectsRequest() { BucketName = bucketName };

            var listObjectsResponse = await s3Client.ListObjectsAsync(request);

            Console.WriteLine($"Bucket {bucketName} contains {listObjectsResponse.S3Objects.Count} objects!");

            string newBucket = "test-new-bucket-creation-with-assumed-role";

            var createBucketResponse = await s3Client.PutBucketAsync(newBucket);
        }

        internal async Task GetCallerIdentityAsync()
        {
            IAmazonSecurityTokenService stsClient = new AmazonSecurityTokenServiceClient(
                credentialProfile.AccessKey,
                credentialProfile.SecretKey,
                _stsConfig
                );

            var getCallerIdentityRequest = new GetCallerIdentityRequest();

            var response = await stsClient.GetCallerIdentityAsync(getCallerIdentityRequest);

            Console.WriteLine($"Get caller Identity:");
            Console.WriteLine($" Account : {response.Account}");
            Console.WriteLine($" User Id : {response.UserId}");
            Console.WriteLine($" User ARN: {response.Arn}");
        }
    }
}
