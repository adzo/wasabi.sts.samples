package org.example;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.*;

import java.net.URI;
import java.net.URISyntaxException;

public class Examples {
    static String s3Uri = "https://s3.wasabisys.com";
    static String stsUri = "https://sts.wasabisys.com";
    static String credentialsProfile = "user";
    static String roleArn = "arn:aws:iam::100000185324:role/user_role";
    public static void getSessionToken() throws URISyntaxException {
        // create the profile credentials provider
        ProfileCredentialsProvider provider = ProfileCredentialsProvider.builder()
                .profileName(credentialsProfile)
                .build();

        // create the stsClient using the profile credentials provider
        StsClient stsClient = StsClient.builder()
                .httpClientBuilder(ApacheHttpClient.builder())
                .endpointOverride(new URI(stsUri))
                .credentialsProvider(provider)
                .build();

        // create the get session token request to be used later
        GetSessionTokenRequest session_token_request = GetSessionTokenRequest.builder()
                .durationSeconds(900)
                .build();

        // getting the session token.
        GetSessionTokenResponse session_token_result = stsClient.getSessionToken(session_token_request);
        Credentials credentials = session_token_result.credentials();

        // retrieving the temporary credentials and the session token and creating AwsSessionCredentials
        // object to be used by the S3 client later
        AwsSessionCredentials sessionCredentials = AwsSessionCredentials.create(
                credentials.accessKeyId(),
                credentials.secretAccessKey(),
                credentials.sessionToken()
        );

        // creating the s3 client using the temporary credentials
        S3Client s3Client = S3Client.builder()
                .httpClientBuilder(ApacheHttpClient.builder())
                .endpointOverride(new URI(s3Uri))
                .credentialsProvider(StaticCredentialsProvider.create(sessionCredentials))
                .build();

        String bucketName = "test-bucket-created-from-sts-credentials";

        // creating the create bucket request
        CreateBucketRequest request = CreateBucketRequest
                .builder()
                .bucket(bucketName)
                .build();

        // creating the bucket!
        CreateBucketResponse response = s3Client.createBucket(request);

        if(response.sdkHttpResponse().isSuccessful()){
            System.out.println(String.format("Bucket '%s' created successfully!", bucketName));
        }else{
            System.out.println(String.format("Error when creating bucket '%s': '%s'", bucketName, response.sdkHttpResponse().statusText()));
        }
    }

    public static void assumeRole() throws URISyntaxException {
        AssumeRoleRequest assume_role = AssumeRoleRequest.builder()
                .roleArn(roleArn)
                .roleSessionName("test-session")
                .durationSeconds(900)
                .build();

        // create the profile credentials provider
        ProfileCredentialsProvider provider = ProfileCredentialsProvider.builder()
                .profileName(credentialsProfile)
                .build();

        // create the stsClient using the profile credentials provider
        StsClient stsClient = StsClient.builder()
                .httpClientBuilder(ApacheHttpClient.builder())
                .endpointOverride(new URI(stsUri))
                .credentialsProvider(provider)
                .build();

        //Get the credentials and session token
        Credentials assumedRoleCredentials = stsClient.assumeRole(assume_role).credentials();

        AwsSessionCredentials sessionCredentials = AwsSessionCredentials.create(
                assumedRoleCredentials.accessKeyId(),
                assumedRoleCredentials.secretAccessKey(),
                assumedRoleCredentials.sessionToken()
        );

        //Create S3 object with temp credentials
        S3Client s3Client = S3Client.builder()
                .httpClientBuilder(ApacheHttpClient.builder())
                .endpointOverride(new URI(s3Uri))
                .credentialsProvider(StaticCredentialsProvider.create(sessionCredentials))
                .build();

        //Perform bucket list operation
        String bucketName = "test-bucket-sts";
        System.out.println("Listing bucket contents " + bucketName + "\n");
        ListObjectsResponse response = s3Client.listObjects(ListObjectsRequest.builder()
                .bucket(bucketName)
                .build());

        System.out.println("No. of Objects = " + response.contents().size());
        long totalSize = 0;
        for (S3Object obj: response.contents()) {
            totalSize += obj.size();
        }
        System.out.println("Total size of objects: "+ totalSize);
    }

    public static void assumeRoleWithPolicy() throws URISyntaxException{
        String denyingPutsPolicy = """
                {
                    "Version": "2012-10-17",
                    "Statement": [
                      {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": ["*"]
                      },
                      {
                        "Effect": "Deny",
                        "Action": "s3:CreateBucket",
                        "Resource": ["*"]
                      }
                    ]
                  }
                """;

        AssumeRoleRequest assume_role = AssumeRoleRequest.builder()
                .roleArn(roleArn)
                .roleSessionName("test-session")
                .durationSeconds(900)
                .policy(denyingPutsPolicy)
                .build();

        // create the profile credentials provider
        ProfileCredentialsProvider provider = ProfileCredentialsProvider.builder()
                .profileName(credentialsProfile)
                .build();

        // create the stsClient using the profile credentials provider
        StsClient stsClient = StsClient.builder()
                .httpClientBuilder(ApacheHttpClient.builder())
                .endpointOverride(new URI(stsUri))
                .credentialsProvider(provider)
                .build();

        //Get the credentials and session token
        Credentials assumedRoleCredentials = stsClient.assumeRole(assume_role).credentials();

        AwsSessionCredentials sessionCredentials = AwsSessionCredentials.create(
                assumedRoleCredentials.accessKeyId(),
                assumedRoleCredentials.secretAccessKey(),
                assumedRoleCredentials.sessionToken()
        );

        //Create S3 object with temp credentials
        S3Client s3Client = S3Client.builder()
                .httpClientBuilder(ApacheHttpClient.builder())
                .endpointOverride(new URI(s3Uri))
                .credentialsProvider(StaticCredentialsProvider.create(sessionCredentials))
                .build();

        //Perform bucket list operation
        String bucketName = "test-bucket-sts";
        System.out.println("Listing bucket contents " + bucketName + "\n");
        ListObjectsResponse listObjectsResponse = s3Client.listObjects(ListObjectsRequest.builder()
                .bucket(bucketName)
                .build());

        System.out.println("Listing bucket content response: " + listObjectsResponse.sdkHttpResponse().statusCode());

        // trying to create a new bucket!
        String newBucket = "test-new-bucket-creation-with-assumed-role";
        CreateBucketRequest request = CreateBucketRequest.builder()
                .bucket(newBucket)
                .build();

        try {
            s3Client.createBucket(request);
        }catch (Exception ex){
            System.out.println("Unable to create bucket: "+ex.getMessage());
        }
    }

    public static void getCallerIdentity() throws URISyntaxException {
        // create the profile credentials provider
        ProfileCredentialsProvider provider = ProfileCredentialsProvider.builder()
                .profileName(credentialsProfile)
                .build();

        // create the stsClient using the profile credentials provider
        StsClient stsClient = StsClient.builder()
                .httpClientBuilder(ApacheHttpClient.builder())
                .endpointOverride(new URI(stsUri))
                .credentialsProvider(provider)
                .build();

        GetCallerIdentityResponse response = stsClient.getCallerIdentity();

        System.out.println("Caller identity: ");
        System.out.println("    Account : "+ response.account());
        System.out.println("    User id : "+ response.userId());
        System.out.println("    User arn: "+ response.arn());
    }

}
