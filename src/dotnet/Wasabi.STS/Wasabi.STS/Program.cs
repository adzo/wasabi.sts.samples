// See https://aka.ms/new-console-template for more information


using Wasabi.STS;

var example = new Examples();


await example.GetCallerIdentityAsync();

await example.GetSessionTokenAsync();

await example.AssumeRoleAsync();

try
{
    await example.AssumeRoleWithPolicyAsync();
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
}

Console.ReadLine();


