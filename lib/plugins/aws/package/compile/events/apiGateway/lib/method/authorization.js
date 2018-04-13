'use strict';

const _ = require('lodash');
const awsArnRegExs = require('../../../../../../utils/arnRegularExpressions');

module.exports = {
  getMethodAuthorization(http) {
    if (_.get(http, 'authorizer.type') === 'AWS_IAM') {
      return {
        Properties: {
          AuthorizationType: 'AWS_IAM',
        },
      };
    }

    if (http.authorizer) {
      const authorizerLogicalId = this.provider.naming
        .getAuthorizerLogicalId(http.authorizer.name);

      let authorizationType = http.authorizer.type;
      if (!authorizationType) {
        const authorizerArn = http.authorizer.arn;
        if (typeof authorizerArn === 'string'
          && awsArnRegExs.cognitoIdpArnExpr.test(authorizerArn)) {
          authorizationType = 'COGNITO_USER_POOLS';
        } else {
          authorizationType = 'CUSTOM';
        }
      }
      
      if (http.authorizer.authorizerId) {
        return {
          Properties: {
            AuthorizationType: authorizationType,
            AuthorizerId: http.authorizer.authorizerId,
          },
        };
      }

      return {
        Properties: {
          AuthorizationType: authorizationType,
          AuthorizerId: { Ref: authorizerLogicalId },
        },
        DependsOn: authorizerLogicalId,
      };
    }

    return {
      Properties: {
        AuthorizationType: 'NONE',
      },
    };
  },
};
