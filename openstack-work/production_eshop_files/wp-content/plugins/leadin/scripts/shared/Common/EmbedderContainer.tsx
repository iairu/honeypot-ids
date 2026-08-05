import { ReactNode } from 'react';
import { BackgroudAppContext } from '../../iframe/useBackgroundApp';
import { useGetEmbedder } from '../../utils/useGetEmbedder';
import LoadingBlock from './LoadingBlock';

interface EmbedderContainerProps {
  children: ReactNode;
}

export default function EmbedderContainer({
  children,
}: EmbedderContainerProps) {
  const { embedder, errorElement, isLoading } = useGetEmbedder();

  if (errorElement) {
    return errorElement;
  }

  if (isLoading) {
    return <LoadingBlock />;
  }

  return (
    <BackgroudAppContext.Provider value={embedder}>
      {children}
    </BackgroudAppContext.Provider>
  );
}
