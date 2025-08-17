export const amplifyConfig = {
  Auth: {
    identityPoolId: 'ap-northeast-2:f0760e93-5199-4d4f-8c2a-b689d6f25600',
    region: 'ap-northeast-2',
    userPoolId: 'ap-northeast-2_Mh01NUKlM',
    userPoolWebClientId: '3sqbfermevq30ntj0empplkd6a',
    authenticationFlowType: 'USER_SRP_AUTH'
  },
  API: {
    endpoints: [
      {
        name: 'DeviceApi',
        endpoint: 'https://6puu14cjdi.execute-api.ap-northeast-2.amazonaws.com/dev',
        region: 'ap-northeast-2'
      }
    ]
  }
};