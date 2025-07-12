# Fix for Data Truncation Issue with securityCode Column

## Issue Description
The application is experiencing a data truncation error when registering new users:
```
com.mysql.cj.jdbc.exceptions.MysqlDataTruncation: Data truncation: Data too long for column 'securityCode' at row 1
```

This occurs because the `securityCode` column in the database is defined with a length that's too small to accommodate the UUID strings (36 characters) that are generated during the registration process.

## Solution

### 1. Execute the SQL Script
Run the following SQL query on your MySQL database:

```sql
ALTER TABLE accounts MODIFY COLUMN securityCode VARCHAR(36) NOT NULL;
```

You can execute this query using:
- MySQL Workbench
- phpMyAdmin
- MySQL command line client
- Any other database management tool

### 2. Verify the Change
After executing the SQL query, you can verify that the column length has been increased by running:

```sql
DESCRIBE accounts securityCode;
```

The output should show that the `securityCode` column is now defined as `VARCHAR(36)`.

### 3. Restart the Application
After making the database change, restart the application to ensure it connects properly to the updated database schema.

## Prevention
The entity class already has the correct column length definition:
```java
@Column(name = "securityCode", nullable = false, length = 36)
private String securityCode;
```

To prevent similar issues in the future, consider:
1. Using a database migration tool like Flyway or Liquibase
2. Setting `spring.jpa.hibernate.ddl-auto=update` in application.properties (for development environments only)